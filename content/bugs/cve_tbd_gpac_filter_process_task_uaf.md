---
title: "CVE-2026-TBD - Use-after-free in GPAC filter-session process task"
date: 2026-10-06T10:05:00+01:00
draft: false
description: ""
weight: -5
tags: ["bug"]
---

## Summary

- **CVE:** CVE-2026-TBD (CVE ID requested via MITRE, batch submission 2026-07-19)
- **Component:** `filter.c` (filter-session core / scheduler)
- **Vulnerability Type:** Use-after-free (write)
- **Vendor:** GPAC
- **Product:** GPAC (libgpac / MP4Box / gpac)
- **Affected Versions:** master branch, commit `9bfcd13401cd1e52f966d03670c433d25952472c` (26.03-DEV)
- **Fix Status:** Fixed upstream: commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22); [issue #3746](https://github.com/gpac/gpac/issues/3746) closed 2026-07-23
- **Severity:** High (7.8 / CVSS 3.1, 8.5 / CVSS 4.0): `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- **Credit:** Salim Largo (2ourc3)

---

## Description

A heap use-after-free write exists in the core of GPAC's filter-session scheduler, in `gf_filter_process_task()`. If a filter's own `process()` callback causes the filter itself to be torn down (e.g. by calling `gf_filter_setup_failure()` internally), the dispatcher that invoked the callback keeps writing to the now-freed `GF_Filter` structure once the callback returns.

This is the core-side manifestation of the leaf-filter lifetime bugs reported alongside it (ISOBMFF reader, AV1 reframer, HTTP input): all are triggered by the same underlying hazard, namely that the filter core does not re-validate a filter's liveness after a callback that may have freed it.

---

## Root cause

`gf_filter_process_task` (`src/filter_core/filter.c:3257`-`3260`):

```c
e = filter->freg->process(filter);       // 3257: callback may destroy `filter`
gf_logs_thread_untag(filter);
filter->in_process_callback = GF_FALSE;  // 3259/3260: use-after-free write
```

A demuxer's `process()` callback triggers teardown of its own filter (freeing the `GF_Filter`), but the core dispatcher keeps touching `filter->...` after the call returns. This is likely related to the PID-init use-after-free reported separately, which shares the same filter-graph lifetime root cause.

---

## Proof of Concept

```sh
afl-clang-fast -O1 -g -fsanitize=address -DGPAC_HAVE_CONFIG_H -I gpac_src -I gpac_src/include \
  harnesses/session_replay.c -L gpac_src/bin/gcc -lgpac -Wl,-rpath,gpac_src/bin/gcc -o session_replay
LD_LIBRARY_PATH=gpac_src/bin/gcc ./session_replay poc_file_uaf_write_filter_process_task
```

Equivalent path: `gf_fs_new(0, GF_FS_SCHEDULER_DIRECT, GF_FS_FLAG_NO_REGULATION)` running `inspect:deep:analyze=on:allp` over the input registered as a `gmem://` blob. The `gpac` / `MP4Box` CLI does not trigger this directly.

### Observed ASan output (trimmed)

```text
==98624==ERROR: AddressSanitizer: heap-use-after-free on address 0x7cfce9ff6444
WRITE of size 4 at 0x7cfce9ff6444 thread T0
    #0 gf_filter_process_task src/filter_core/filter.c:3260:30
    #1 gf_fs_post_task_ex src/filter_core/filter_session.c:973:3
    #2 gf_filter_post_process_task_internal src/filter_core/filter.c
    ...

0x7cfce9ff6444 is located 196 bytes inside of 936-byte region
freed by thread T0 here:
    #0 free (asan interceptor)
    #1 gf_filter_del src/filter_core/filter.c:804:2
    #2 gf_filter_setup_failure_task src/filter_core/filter.c:3668:2
    ...
    #7 txtin_process src/filters/load_text.c:4188:4
    #8 gf_filter_process_task src/filter_core/filter.c:3257:7
    ...

SUMMARY: AddressSanitizer: heap-use-after-free src/filter_core/filter.c:3260:30 in gf_filter_process_task
```

---

## Fix

Fixed upstream in commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22), titled *"fuzz: fix mem errors from filter setup_failure() and others"*, a single patch that closed all ten vulnerabilities reported in this batch.

This is the bug whose fix anchors the whole batch: `gf_filter_setup_failure_task()` (`src/filter_core/filter.c`) now defers a filter's teardown instead of freeing it synchronously while a task for that same filter (such as the `process()` call that triggered the teardown) is still on the call stack:

```c
/* Defer teardown if a task for this filter is currently executing on the direct-call stack.
   gf_filter_process_task clears in_process_callback after freg->process() returns;
   gf_fs_post_task_ex clears DIRECT_SCHEDULED after any direct-call task returns.
   Running the teardown synchronously here would free the filter mid-stack. */
if (f->in_process_callback || f->scheduled_for_next_task == GF_FILTER_DIRECT_SCHEDULED) {
    task->requeue_request = GF_TRUE;
    return;
}
```

`gf_filter_process_task()` can now safely write `filter->in_process_callback = GF_FALSE` after `process()` returns, because the filter is guaranteed not to have been freed mid-call; the actual teardown is deferred to a later task, after the stack has unwound. The upstream maintainer (`aureliendavid`) also hardened a handful of related probe functions (`load_text.c`, `ff_dmx.c`) as part of the same commit.

---

## Impact

Use-after-free write in the core filter scheduler, reachable by any untrusted input that makes a filter self-destruct during processing (observed via the text/subtitle loader, `load_text.c`). Primary impact is denial of service (crash); heap corruption on the freed 936-byte region raises the possibility of further exploitation.

---

## Timeline

| Date | Action |
|---|---|
| 2026-07-19 | Reported upstream ([issue #3746](https://github.com/gpac/gpac/issues/3746)) |
| 2026-07-21 | Session-replay harness shared with maintainer on request |
| 2026-07-22 | Fixed upstream, commit `03e5b1c` |
| 2026-07-23 | Issue closed |

---

## References

* **GitHub issue:** [gpac/gpac#3746](https://github.com/gpac/gpac/issues/3746) (closed)
* **Fix commit:** [03e5b1c23a52c2524d0f06f9909d56de5825292e](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e)
* **Discoverer:** Salim Largo (2ourc3), via fuzzing (AFL++ / libFuzzer + AddressSanitizer)
* **CVE status:** Requested from MITRE as part of a 10-vulnerability batch submission; CVE ID pending
