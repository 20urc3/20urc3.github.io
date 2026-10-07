---
title: "CVE-2026-TBD - Use-after-free write in GPAC AV1 reframer (OBU parse error)"
date: 2026-10-06T10:03:00+01:00
draft: false
description: ""
weight: -7
tags: ["bug"]
---

## Summary

- **CVE:** CVE-2026-TBD (CVE ID requested via MITRE, batch submission 2026-07-19)
- **Component:** `reframe_av1.c` (AV1 reframer / demuxer filter)
- **Vulnerability Type:** Use-after-free (write)
- **Vendor:** GPAC
- **Product:** GPAC (libgpac / MP4Box / gpac)
- **Affected Versions:** master branch, commit `9bfcd13401cd1e52f966d03670c433d25952472c` (26.03-DEV)
- **Fix Status:** Fixed upstream: commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22); [issue #3744](https://github.com/gpac/gpac/issues/3744) closed 2026-07-23
- **Severity:** High (7.8 / CVSS 3.1, 8.5 / CVSS 4.0): `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- **Credit:** Salim Largo (2ourc3)

---

## Description

A heap use-after-free write exists in GPAC's AV1 reframer, in `av1dmx_check_format()`. When OBU (Open Bitstream Unit) parsing fails on a crafted AV1 stream, the filter is torn down via `gf_filter_setup_failure()`, which can free the demuxer's context, but the function then writes to that freed context on its way out.

---

## Root cause

`av1dmx_check_format` (`src/filters/reframe_av1.c:303`):

```c
gf_filter_setup_failure(filter, e);   // may destroy the filter + `ctx`
ctx->bsmode = UNSUPPORTED;            // 303: use-after-free write
return e;
```

After `gf_filter_setup_failure()` frees `ctx`, the code writes `ctx->bsmode`. This is the first of two write sites in the same function (the OBU-parse-error branch), with an [identical sibling write at line 310](/bugs/cve_tbd_gpac_av1_check_format_310_uaf/) reached via a different error condition in the same code path.

---

## Proof of Concept

```sh
afl-clang-fast -O1 -g -fsanitize=address -DGPAC_HAVE_CONFIG_H -I gpac_src -I gpac_src/include \
  harnesses/session_replay.c -L gpac_src/bin/gcc -lgpac -Wl,-rpath,gpac_src/bin/gcc -o session_replay
LD_LIBRARY_PATH=gpac_src/bin/gcc ./session_replay poc_file_uaf_write_av1_check_format_303
```

Equivalent path: `gf_fs_new(0, GF_FS_SCHEDULER_DIRECT, GF_FS_FLAG_NO_REGULATION)` running `inspect:deep:analyze=on:allp` over the input registered as a `gmem://` blob. The `gpac` / `MP4Box` CLI does not trigger this directly.

### Observed ASan output (trimmed)

```text
==98657==ERROR: AddressSanitizer: heap-use-after-free on address 0x7e4f34c08438
WRITE of size 4 at 0x7e4f34c08438 thread T0
    #0 av1dmx_check_format src/filters/reframe_av1.c:303:16
    #1 av1dmx_process_buffer src/filters/reframe_av1.c:1229:6
    #2 av1dmx_process src/filters/reframe_av1.c:1288:9
    ...

0x7e4f34c08438 is located 56 bytes inside of 35768-byte region
freed by thread T0 here:
    #0 free (asan interceptor)
    #1 gf_filter_del src/filter_core/filter.c:710:27
    #2 gf_filter_setup_failure_task src/filter_core/filter.c:3668:2
    ...
    #7 av1dmx_check_format src/filters/reframe_av1.c:302:4
    #8 av1dmx_process_buffer src/filters/reframe_av1.c:1229:6
    ...

SUMMARY: AddressSanitizer: heap-use-after-free src/filters/reframe_av1.c:303:16 in av1dmx_check_format
```

---

## Fix

Fixed upstream in commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22), titled *"fuzz: fix mem errors from filter setup_failure() and others"*, a single patch that closed all ten vulnerabilities reported in this batch.

Rather than special-casing `av1dmx_check_format()`, the fix addresses the shared root cause in `gf_filter_setup_failure_task()` (`src/filter_core/filter.c`): teardown of the filter (and its `ctx`) is now deferred instead of happening synchronously while a task for that filter is still executing:

```c
if (f->in_process_callback || f->scheduled_for_next_task == GF_FILTER_DIRECT_SCHEDULED) {
    task->requeue_request = GF_TRUE;
    return;
}
```

With teardown requeued, `ctx` is still valid when `av1dmx_check_format()` assigns `ctx->bsmode` on its way out.

---

## Impact

Use-after-free write when demuxing untrusted AV1/OBU (IVF/OBU/AV1-in-MP4) input. Primary impact is denial of service (crash); heap corruption on the freed 35768-byte region raises the possibility of further exploitation.

---

## Timeline

| Date | Action |
|---|---|
| 2026-07-19 | Reported upstream ([issue #3744](https://github.com/gpac/gpac/issues/3744)) |
| 2026-07-21 | Session-replay harness shared with maintainer on request |
| 2026-07-22 | Fixed upstream, commit `03e5b1c` |
| 2026-07-23 | Issue closed |

---

## References

* **GitHub issue:** [gpac/gpac#3744](https://github.com/gpac/gpac/issues/3744) (closed)
* **Fix commit:** [03e5b1c23a52c2524d0f06f9909d56de5825292e](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e)
* **Discoverer:** Salim Largo (2ourc3), via fuzzing (AFL++ / libFuzzer + AddressSanitizer)
* **CVE status:** Requested from MITRE as part of a 10-vulnerability batch submission; CVE ID pending
