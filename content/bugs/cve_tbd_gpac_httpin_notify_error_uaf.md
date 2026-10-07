---
title: "CVE-2026-TBD - Use-after-free write in GPAC HTTP input filter error path"
date: 2026-10-06T10:00:00+01:00
draft: false
description: ""
weight: -10
tags: ["bug"]
---

## Summary

- **CVE:** CVE-2026-TBD (CVE ID requested via MITRE, batch submission 2026-07-19)
- **Component:** `in_http.c` (HTTP input filter)
- **Vulnerability Type:** Use-after-free (write)
- **Vendor:** GPAC
- **Product:** GPAC (libgpac / MP4Box / gpac)
- **Affected Versions:** master branch, commit `9bfcd13401cd1e52f966d03670c433d25952472c` (26.03-DEV; only HEAD is supported per GPAC policy)
- **Fix Status:** Fixed upstream: commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22); [issue #3747](https://github.com/gpac/gpac/issues/3747) closed 2026-07-23
- **Severity:** Critical (9.2): `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N`
- **Credit:** Salim Largo (2ourc3)

---

## Description

A heap use-after-free write exists in GPAC's HTTP input filter, in `httpin_notify_error()`. When the filter's error-notification path runs during session setup, `gf_filter_setup_failure()` can tear down the filter (freeing its context), but the function continues to write to that freed context afterward.

This is the only one of the ten reported GPAC defects reachable over the network without local user interaction, which pushes its CVSS score to **9.2 (Critical)**. A remote server (or a man-in-the-middle on an unauthenticated HTTP fetch) can trigger it simply by causing GPAC's HTTP input to hit an error path while fetching a resource.

---

## Root cause

`httpin_notify_error` (`src/filters/in_http.c:92`):

```c
if (!ctx->initial_ack_done) {
    gf_filter_setup_failure(filter, e);   // may destroy the filter + `ctx`
    ctx->initial_ack_done = GF_TRUE;      // 92: use-after-free write
}
```

`gf_filter_setup_failure()` can free the HTTP input context `ctx` (via `gf_filter_setup_failure_task` → `gf_filter_del`), after which the code unconditionally assigns `ctx->initial_ack_done`. This is the same "setup-failure-then-use" pattern observed in the AV1 reframer and ISOBMFF reader bugs reported alongside this one. All appear to share a common root cause in how `gf_filter_setup_failure()` lifetime interacts with filter-local state.

---

## Proof of Concept

These filter-session crashes reproduce through libgpac's DIRECT-scheduler deep-inspect code path; the `gpac` / `MP4Box` CLI does not trigger them directly. A single-shot replay harness loads the PoC through `gf_fs_load_source()`:

```sh
afl-clang-fast -O1 -g -fsanitize=address -DGPAC_HAVE_CONFIG_H -I gpac_src -I gpac_src/include \
  harnesses/session_replay.c -L gpac_src/bin/gcc -lgpac -Wl,-rpath,gpac_src/bin/gcc -o session_replay
LD_LIBRARY_PATH=gpac_src/bin/gcc ./session_replay poc_file_uaf_write_httpin_notify_error
```

Equivalent path: `gf_fs_new(0, GF_FS_SCHEDULER_DIRECT, GF_FS_FLAG_NO_REGULATION)` running `inspect:deep:analyze=on:allp` over the input registered as a `gmem://` blob.

### Observed ASan output (trimmed)

```text
==98679==ERROR: AddressSanitizer: heap-use-after-free on address 0x7c393f9e093c
WRITE of size 4 at 0x7c393f9e093c thread T0
    #0 httpin_notify_error src/filters/in_http.c:92:26
    #1 httpin_process src/filters/in_http.c:528:5
    #2 gf_filter_process_task src/filter_core/filter.c:3257:7
    ...

0x7c393f9e093c is located 60 bytes inside of 160-byte region
freed by thread T0 here:
    #0 free (asan interceptor)
    #1 gf_filter_del src/filter_core/filter.c:710:27
    #2 gf_filter_setup_failure_task src/filter_core/filter.c:3668:2
    ...
    #7 httpin_notify_error src/filters/in_http.c:91:4
    #8 httpin_process src/filters/in_http.c:528:5
    ...

SUMMARY: AddressSanitizer: heap-use-after-free src/filters/in_http.c:92:26 in httpin_notify_error
```

---

## Fix

Fixed upstream in commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22), titled *"fuzz: fix mem errors from filter setup_failure() and others"*, a single patch that closed all ten vulnerabilities reported in this batch.

Rather than patching `httpin_notify_error()` itself, the fix addresses the shared root cause in `gf_filter_setup_failure_task()` (`src/filter_core/filter.c`): teardown is now deferred if a task for the filter is still executing on the call stack, instead of freeing the filter synchronously underneath it.

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

With teardown requeued instead of immediate, `httpin_notify_error()` no longer writes through a `ctx` pointer that was just freed underneath it.

---

## Impact

Use-after-free write in the HTTP input error path, reachable when GPAC processes an untrusted input/URL (including over the network, with no user interaction required). Primary impact is denial of service (crash); heap corruption on the freed 160-byte region raises the possibility of further exploitation depending on heap layout and allocator state at the time of the free.

---

## Timeline

| Date | Action |
|---|---|
| 2026-07-19 | Reported upstream ([issue #3747](https://github.com/gpac/gpac/issues/3747)) |
| 2026-07-21 | Session-replay harness shared with maintainer on request |
| 2026-07-22 | Maintainer flagged the attachment was the markdown writeup, not the PoC file; PoC re-uploaded |
| 2026-07-22 | Fixed upstream, commit `03e5b1c` |
| 2026-07-23 | Issue closed |

---

## References

* **GitHub issue:** [gpac/gpac#3747](https://github.com/gpac/gpac/issues/3747) (closed)
* **Fix commit:** [03e5b1c23a52c2524d0f06f9909d56de5825292e](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e)
* **Discoverer:** Salim Largo (2ourc3), via fuzzing (AFL++ / libFuzzer + AddressSanitizer)
* **CVE status:** Requested from MITRE as part of a 10-vulnerability batch submission; CVE ID pending
