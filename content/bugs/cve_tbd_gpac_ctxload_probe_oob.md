---
title: "CVE-2026-TBD - Heap buffer overflow in GPAC BT/XMT scene loader probe"
date: 2026-10-06T10:08:00+01:00
draft: false
description: ""
weight: -2
tags: ["bug"]
---

## Summary

- **CVE:** CVE-2026-TBD (CVE ID requested via MITRE, batch submission 2026-07-19)
- **Component:** `load_bt_xmt.c` (BT/XMT scene loader format probe)
- **Vulnerability Type:** Heap buffer overflow (1-byte out-of-bounds read)
- **Vendor:** GPAC
- **Product:** GPAC (libgpac / MP4Box / gpac)
- **Affected Versions:** master branch, commit `9bfcd13401cd1e52f966d03670c433d25952472c` (26.03-DEV)
- **Fix Status:** Fixed upstream: commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22); [issue #3741](https://github.com/gpac/gpac/issues/3741) closed 2026-07-23
- **Severity:** Medium (5.5 / CVSS 3.1, 5.1 / CVSS 4.0): `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H`
- **Credit:** Salim Largo (2ourc3)

---

## Description

A heap-buffer-overflow (1-byte out-of-bounds read) exists in GPAC's BT/XMT scene-loader format probe: `strncmp` reads past the end of the probe buffer when checking for a `<!DOCTYPE` marker.

Because format probing runs on any input before its real format is known, this is reachable simply by having GPAC inspect an untrusted file, not just one that is ultimately recognized as BT/XMT.

---

## Root cause

`ctxload_probe_data` (`src/filters/load_bt_xmt.c:867`):

```c
while (probe_size && probe_data[0] && strchr("\n\r\t ", probe_data[0])) { probe_data++; probe_size--; }
...
while (1) {
    if (!strncmp(probe_data, "<!DOCTYPE", 9)) { ... }   // 867: reads up to 9 bytes
```

After the leading-whitespace strip, `probe_data` may have fewer than 9 bytes remaining (and is not guaranteed to be NUL-terminated), but the marker checks read a fixed number of bytes without re-checking `probe_size` first, reading past the probe buffer.

---

## Proof of Concept

```sh
afl-clang-fast -O1 -g -fsanitize=address -DGPAC_HAVE_CONFIG_H -I gpac_src -I gpac_src/include \
  harnesses/session_replay.c -L gpac_src/bin/gcc -lgpac -Wl,-rpath,gpac_src/bin/gcc -o session_replay
LD_LIBRARY_PATH=gpac_src/bin/gcc ./session_replay poc_file_heap_bof_read_ctxload_probe
```

Equivalent path: `gf_fs_new(0, GF_FS_SCHEDULER_DIRECT, GF_FS_FLAG_NO_REGULATION)` running `inspect:deep:analyze=on:allp` over the input registered as a `gmem://` blob. The `gpac` / `MP4Box` CLI does not trigger this directly.

### Observed ASan output (trimmed)

```text
==98668==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7bd9f8de4f52
READ of size 1 at 0x7bd9f8de4f52 thread T0
    #0 strncmp (asan interceptor)
    #1 ctxload_probe_data src/filters/load_bt_xmt.c:867:8
    #2 gf_filter_pid_raw_new src/filter_core/filter.c:4801:13
    ...

0x7bd9f8de4f52 is located 0 bytes after 2-byte region

SUMMARY: AddressSanitizer: heap-buffer-overflow src/filters/load_bt_xmt.c:867:8 in ctxload_probe_data
```

---

## Fix

Fixed upstream in commit [`03e5b1c`](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e) (2026-07-22), titled *"fuzz: fix mem errors from filter setup_failure() and others"*, a single patch that closed all ten vulnerabilities reported in this batch.

`ctxload_probe_data()` (`src/filters/load_bt_xmt.c`) gained two early-exit guards for an exhausted probe buffer: one right after the leading-whitespace strip, and another after locating the first XML element, both before any further fixed-length `strncmp` / `gf_strmemstr` calls:

```c
if (!probe_size) goto exit;
```

---

## Impact

Out-of-bounds heap read during format probing of any untrusted input (probing runs before the format is known). Denial of service and potential information disclosure.

---

## Timeline

| Date | Action |
|---|---|
| 2026-07-19 | Reported upstream ([issue #3741](https://github.com/gpac/gpac/issues/3741)) |
| 2026-07-21 | Session-replay harness shared with maintainer on request |
| 2026-07-22 | Fixed upstream, commit `03e5b1c` |
| 2026-07-23 | Issue closed |

---

## References

* **GitHub issue:** [gpac/gpac#3741](https://github.com/gpac/gpac/issues/3741) (closed)
* **Fix commit:** [03e5b1c23a52c2524d0f06f9909d56de5825292e](https://github.com/gpac/gpac/commit/03e5b1c23a52c2524d0f06f9909d56de5825292e)
* **Discoverer:** Salim Largo (2ourc3), via fuzzing (AFL++ / libFuzzer + AddressSanitizer)
* **CVE status:** Requested from MITRE as part of a 10-vulnerability batch submission; CVE ID pending
