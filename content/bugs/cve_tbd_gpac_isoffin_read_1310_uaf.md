---
title: "CVE-2026-TBD - Use-after-free write in GPAC ISOBMFF reader (moof after mdat)"
date: 2026-10-06T10:02:00+01:00
draft: false
description: ""
weight: -8
tags: ["bug"]
---

## Summary

- **CVE:** CVE-2026-TBD (CVE ID requested via MITRE, batch submission 2026-07-19)
- **Component:** `isoffin_read.c` (ISOBMFF / MP4 reader filter)
- **Vulnerability Type:** Use-after-free (write)
- **Vendor:** GPAC
- **Product:** GPAC (libgpac / MP4Box / gpac)
- **Affected Versions:** master branch, commit `9bfcd13401cd1e52f966d03670c433d25952472c` (26.03-DEV)
- **Fix Status:** Fixed upstream: commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22); [issue #3749](https://github.com/gpac/gpac/issues/3749) closed 2026-07-23
- **Severity:** High (8.5): `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N`
- **Credit:** Salim Largo (2ourc3)

---

## Description

A second heap use-after-free write exists in the same function as [the sibling bug at `isoffin_read.c:1301`](/bugs/cve_tbd_gpac_isoffin_read_1301_uaf/), this time in the "unsupported `moof`-after-`mdat`" error branch of GPAC's ISOBMFF reader: a non-fragmented file where a `moof` box unexpectedly appears after an `mdat` box, with no file cache available.

---

## Root cause

`isoffin_push_buffer` (`src/filters/isoffin_read.c:1310`), the unsupported `mdat`-first branch:

```c
case GF_4CC('m','d','a','t'):
    GF_LOG(...);
    gf_filter_setup_failure(filter, GF_NOT_SUPPORTED);  // may free the `read` udta
    read->mem_load_mode = 0;                            // 1310: use-after-free write
    read->in_error = GF_NOT_SUPPORTED;
```

Identical pattern to the line-1301 write: `gf_filter_setup_failure()` frees the reader context, then the code writes `read->...`. Both write sites live in the same function and are reached via different malformed-input conditions, suggesting a single underlying fix (checking the filter's live/failed state, or avoiding the write entirely, right after calling `gf_filter_setup_failure()`) would resolve both.

---

## Proof of Concept

```sh
afl-clang-fast -O1 -g -fsanitize=address -DGPAC_HAVE_CONFIG_H -I gpac_src -I gpac_src/include \
  harnesses/session_replay.c -L gpac_src/bin/gcc -lgpac -Wl,-rpath,gpac_src/bin/gcc -o session_replay
LD_LIBRARY_PATH=gpac_src/bin/gcc ./session_replay poc_file_uaf_write_isoffin_read_1310
```

Equivalent path: `gf_fs_new(0, GF_FS_SCHEDULER_DIRECT, GF_FS_FLAG_NO_REGULATION)` running `inspect:deep:analyze=on:allp` over the input registered as a `gmem://` blob. As with the other filter-session bugs, the `gpac` / `MP4Box` CLI does not trigger this directly; it reproduces through the DIRECT-scheduler deep-inspect path.

### Observed ASan output (trimmed)

```text
==98635==ERROR: AddressSanitizer: heap-use-after-free on address 0x7cebed7f305c
WRITE of size 4 at 0x7cebed7f305c thread T0
    #0 isoffin_push_buffer src/filters/isoffin_read.c:1310:25
    #1 isoffin_process src/filters/isoffin_read.c:1463:5
    #2 gf_filter_process_task src/filter_core/filter.c:3257:7
    ...

0x7cebed7f305c is located 348 bytes inside of 464-byte region
freed by thread T0 here:
    #0 free (asan interceptor)
    #1 gf_filter_del src/filter_core/filter.c:710:27
    #2 gf_filter_setup_failure_task src/filter_core/filter.c:3668:2
    ...
    #7 isoffin_push_buffer src/filters/isoffin_read.c:1309:5
    #8 isoffin_process src/filters/isoffin_read.c:1463:5
    ...

SUMMARY: AddressSanitizer: heap-use-after-free src/filters/isoffin_read.c:1310:25 in isoffin_push_buffer
```

---

## Fix

Fixed upstream in commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22), titled *"fuzz: fix mem errors from filter setup_failure() and others"*, a single patch that closed all ten vulnerabilities reported in this batch.

Same fix as [the sibling bug at line 1301](/bugs/cve_tbd_gpac_isoffin_read_1301_uaf/): `gf_filter_setup_failure_task()` (`src/filter_core/filter.c`) now defers teardown instead of freeing the filter synchronously mid-call:

```c
if (f->in_process_callback || f->scheduled_for_next_task == GF_FILTER_DIRECT_SCHEDULED) {
    task->requeue_request = GF_TRUE;
    return;
}
```

plus the matching guard in `gf_fs_load_source_dest_internal()` (`src/filter_core/filter_session.c`) that refuses to hand back a filter already marked `removed`.

---

## Impact

Use-after-free write on ISOBMFF demux of untrusted input. Primary impact is denial of service (crash); heap corruption on the freed 464-byte region raises the possibility of further exploitation.

---

## Timeline

| Date | Action |
|---|---|
| 2026-07-19 | Reported upstream ([issue #3749](https://github.com/gpac/gpac/issues/3749)) |
| 2026-07-21 | Session-replay harness shared with maintainer on request |
| 2026-07-22 | Fixed upstream, commit `03e5b1c` |
| 2026-07-23 | Issue closed |

---

## References

* **GitHub issue:** [gpac/gpac#3749](https://github.com/gpac/gpac/issues/3749) (closed)
* **Fix commit:** [03e5b1c23a52c2524d0f06f9909d56de5825292e](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e)
* **Discoverer:** Salim Largo (2ourc3), via fuzzing (AFL++ / libFuzzer + AddressSanitizer)
* **CVE status:** Requested from MITRE as part of a 10-vulnerability batch submission; CVE ID pending
