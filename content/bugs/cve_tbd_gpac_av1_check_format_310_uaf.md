---
title: "CVE-2026-TBD - Use-after-free write in GPAC AV1 reframer (missing temporal delimiter)"
date: 2026-10-06T10:04:00+01:00
draft: false
description: ""
weight: -6
tags: ["bug"]
---

## Summary

- **CVE:** CVE-2026-TBD (CVE ID requested via MITRE, batch submission 2026-07-19)
- **Component:** `reframe_av1.c` (AV1 reframer / demuxer filter)
- **Vulnerability Type:** Use-after-free (write)
- **Vendor:** GPAC
- **Product:** GPAC (libgpac / MP4Box / gpac)
- **Affected Versions:** master branch, commit `9bfcd13401cd1e52f966d03670c433d25952472c` (26.03-DEV)
- **Fix Status:** Fixed upstream: commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22); [issue #3745](https://github.com/gpac/gpac/issues/3745) closed 2026-07-23
- **Severity:** High (7.8 / CVSS 3.1, 8.5 / CVSS 4.0): `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- **Credit:** Salim Largo (2ourc3)

---

## Description

A second heap use-after-free write exists in the same function as [the sibling bug at `reframe_av1.c:303`](/bugs/cve_tbd_gpac_av1_check_format_303_uaf/), this time reached when a stream has no timescale and never carries a temporal delimiter OBU.

---

## Root cause

`av1dmx_check_format` (`src/filters/reframe_av1.c:310`):

```c
if (!ctx->timescale && !ctx->state.has_temporal_delim) {
    GF_LOG(...);
    gf_filter_setup_failure(filter, e);  // may destroy the filter + `ctx`
    ctx->bsmode = UNSUPPORTED;           // 310: use-after-free write
    return e;
}
```

`gf_filter_setup_failure()` frees the AV1 demuxer context `ctx`, then the code assigns `ctx->bsmode`. Same function/pattern as the line-303 write, and the same setup-failure-then-use class seen across the ISOBMFF and HTTP input bugs reported alongside this one.

---

## Proof of Concept

```sh
afl-clang-fast -O1 -g -fsanitize=address -DGPAC_HAVE_CONFIG_H -I gpac_src -I gpac_src/include \
  harnesses/session_replay.c -L gpac_src/bin/gcc -lgpac -Wl,-rpath,gpac_src/bin/gcc -o session_replay
LD_LIBRARY_PATH=gpac_src/bin/gcc ./session_replay poc_file_uaf_write_av1_check_format_310
```

Equivalent path: `gf_fs_new(0, GF_FS_SCHEDULER_DIRECT, GF_FS_FLAG_NO_REGULATION)` running `inspect:deep:analyze=on:allp` over the input registered as a `gmem://` blob. The `gpac` / `MP4Box` CLI does not trigger this directly.

### Observed ASan output (trimmed)

```text
==98646==ERROR: AddressSanitizer: heap-use-after-free on address 0x7e9748a08438
WRITE of size 4 at 0x7e9748a08438 thread T0
    #0 av1dmx_check_format src/filters/reframe_av1.c:310:16
    #1 av1dmx_process_buffer src/filters/reframe_av1.c:1229:6
    #2 av1dmx_process src/filters/reframe_av1.c:1381:6
    ...

0x7e9748a08438 is located 56 bytes inside of 35768-byte region
freed by thread T0 here:
    #0 free (asan interceptor)
    #1 gf_filter_del src/filter_core/filter.c:710:27
    #2 gf_filter_setup_failure_task src/filter_core/filter.c:3668:2
    ...
    #7 av1dmx_check_format src/filters/reframe_av1.c:309:4
    #8 av1dmx_process_buffer src/filters/reframe_av1.c:1229:6
    ...

SUMMARY: AddressSanitizer: heap-use-after-free src/filters/reframe_av1.c:310:16 in av1dmx_check_format
```

---

## Fix

Fixed upstream in commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22), titled *"fuzz: fix mem errors from filter setup_failure() and others"*, a single patch that closed all ten vulnerabilities reported in this batch.

Same fix as [the sibling bug at line 303](/bugs/cve_tbd_gpac_av1_check_format_303_uaf/): `gf_filter_setup_failure_task()` (`src/filter_core/filter.c`) now defers teardown instead of freeing `ctx` synchronously mid-call:

```c
if (f->in_process_callback || f->scheduled_for_next_task == GF_FILTER_DIRECT_SCHEDULED) {
    task->requeue_request = GF_TRUE;
    return;
}
```

---

## Impact

Use-after-free write when demuxing untrusted AV1/OBU (IVF/OBU/AV1-in-MP4) input. Primary impact is denial of service (crash); heap corruption on the freed 35768-byte region raises the possibility of further exploitation.

---

## Timeline

| Date | Action |
|---|---|
| 2026-07-19 | Reported upstream ([issue #3745](https://github.com/gpac/gpac/issues/3745)) |
| 2026-07-21 | Session-replay harness shared with maintainer on request |
| 2026-07-22 | Fixed upstream, commit `03e5b1c` |
| 2026-07-23 | Issue closed |

---

## References

* **GitHub issue:** [gpac/gpac#3745](https://github.com/gpac/gpac/issues/3745) (closed)
* **Fix commit:** [03e5b1c23a52c2524d0f06f9909d56de5825292e](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e)
* **Discoverer:** Salim Largo (2ourc3), via fuzzing (AFL++ / libFuzzer + AddressSanitizer)
* **CVE status:** Requested from MITRE as part of a 10-vulnerability batch submission; CVE ID pending
