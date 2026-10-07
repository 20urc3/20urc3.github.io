---
title: "CVE-2026-TBD - Use-after-free write in GPAC ISOBMFF reader (fragmented MP4)"
date: 2026-10-06T10:01:00+01:00
draft: false
description: ""
weight: -9
tags: ["bug"]
---

## Summary

- **CVE:** CVE-2026-TBD (CVE ID requested via MITRE, batch submission 2026-07-19)
- **Component:** `isoffin_read.c` (ISOBMFF / MP4 reader filter)
- **Vulnerability Type:** Use-after-free (write)
- **Vendor:** GPAC
- **Product:** GPAC (libgpac / MP4Box / gpac)
- **Affected Versions:** master branch, commit `9bfcd13401cd1e52f966d03670c433d25952472c` (26.03-DEV)
- **Fix Status:** Fixed upstream: commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22); [issue #3748](https://github.com/gpac/gpac/issues/3748) closed 2026-07-23
- **Severity:** High (8.5): `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N`
- **Credit:** Salim Largo (2ourc3)

---

## Description

A heap use-after-free write exists in GPAC's ISOBMFF (MP4/MOV) reader, in `isoffin_push_buffer()`. While demuxing a crafted fragmented MP4/MOV file, an error branch tears down the reader filter and then keeps writing to the now-freed reader context.

---

## Root cause

`isoffin_push_buffer` (`src/filters/isoffin_read.c:1301`):

```c
if (e && (e != GF_ISOM_INCOMPLETE_FILE)) {
    gf_filter_setup_failure(filter, e);   // may tear down the filter + its `read` udta
    read->mem_load_mode = 0;              // 1301: use-after-free write
    read->in_error = e;
    return;
}
```

`gf_filter_setup_failure()` can destroy the filter and free its `GF_ISOMReader` context `read`, yet the function keeps assigning to `read->...` afterward. This is the same pattern (and likely same root cause) as the sibling write at line 1310 (reported separately), and the same "setup-failure-then-use" class as the AV1 and HTTP input bugs reported alongside this one.

---

## Proof of Concept

These filter-session crashes reproduce through libgpac's DIRECT-scheduler deep-inspect code path; the `gpac` / `MP4Box` CLI does not trigger them directly.

```sh
afl-clang-fast -O1 -g -fsanitize=address -DGPAC_HAVE_CONFIG_H -I gpac_src -I gpac_src/include \
  harnesses/session_replay.c -L gpac_src/bin/gcc -lgpac -Wl,-rpath,gpac_src/bin/gcc -o session_replay
LD_LIBRARY_PATH=gpac_src/bin/gcc ./session_replay poc_file_uaf_write_isoffin_read_1301
```

Equivalent path: `gf_fs_new(0, GF_FS_SCHEDULER_DIRECT, GF_FS_FLAG_NO_REGULATION)` running `inspect:deep:analyze=on:allp` over the input registered as a `gmem://` blob.

### Observed ASan output (trimmed)

```text
==98613==ERROR: AddressSanitizer: heap-use-after-free on address 0x7cadcedf305c
WRITE of size 4 at 0x7cadcedf305c thread T0
    #0 isoffin_push_buffer src/filters/isoffin_read.c:1301:24
    #1 isoffin_process src/filters/isoffin_read.c:1463:5
    #2 gf_filter_process_task src/filter_core/filter.c:3257:7
    ...

0x7cadcedf305c is located 348 bytes inside of 464-byte region
freed by thread T0 here:
    #0 free (asan interceptor)
    #1 gf_filter_del src/filter_core/filter.c:710:27
    #2 gf_filter_setup_failure_task src/filter_core/filter.c:3668:2
    ...
    #7 isoffin_push_buffer src/filters/isoffin_read.c:1300:4
    #8 isoffin_process src/filters/isoffin_read.c:1463:5
    ...

SUMMARY: AddressSanitizer: heap-use-after-free src/filters/isoffin_read.c:1301:24 in isoffin_push_buffer
```

---

## Fix

Fixed upstream in commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22), titled *"fuzz: fix mem errors from filter setup_failure() and others"*, a single patch that closed all ten vulnerabilities reported in this batch.

The core fix is in `gf_filter_setup_failure_task()` (`src/filter_core/filter.c`): teardown of the filter is now deferred rather than performed synchronously while a task for that filter is still running, which is what let `isoffin_push_buffer()` keep writing to `read` after it had just been freed:

```c
if (f->in_process_callback || f->scheduled_for_next_task == GF_FILTER_DIRECT_SCHEDULED) {
    task->requeue_request = GF_TRUE;
    return;
}
```

A complementary fix in `gf_fs_load_source_dest_internal()` (`src/filter_core/filter_session.c`) makes sure a filter marked `removed` by a deferred setup failure is never handed back to the caller as if it were live:

```c
if (filter && filter->removed) {
    if (err && !*err)
        *err = filter->session->last_connect_error ? filter->session->last_connect_error : GF_SERVICE_ERROR;
    return NULL;
}
```

---

## Impact

Use-after-free write reachable by any application demuxing untrusted ISOBMFF (MP4/MOV/3GP/fragmented) input through GPAC/libgpac. Primary impact is denial of service (crash); heap corruption on the freed 464-byte region raises the possibility of further exploitation.

---

## Timeline

| Date | Action |
|---|---|
| 2026-07-19 | Reported upstream ([issue #3748](https://github.com/gpac/gpac/issues/3748)) |
| 2026-07-21 | Session-replay harness shared with maintainer on request |
| 2026-07-22 | Fixed upstream, commit `03e5b1c` |
| 2026-07-23 | Issue closed |

---

## References

* **GitHub issue:** [gpac/gpac#3748](https://github.com/gpac/gpac/issues/3748) (closed)
* **Fix commit:** [03e5b1c23a52c2524d0f06f9909d56de5825292e](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e)
* **Discoverer:** Salim Largo (2ourc3), via fuzzing (AFL++ / libFuzzer + AddressSanitizer)
* **CVE status:** Requested from MITRE as part of a 10-vulnerability batch submission; CVE ID pending
