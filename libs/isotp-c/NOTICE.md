# isotp-c

Upstream: https://github.com/openxc/isotp-c
License: BSD-3-Clause (SPDX: BSD-3-Clause) — Copyright (c) 2013 Ford Motor
Company. The full license text is in the `LICENSE` file in this folder,
vendored verbatim from upstream.

Vendored at the pre-fix commit for CVE-2026-37535 (out-of-bounds write in the
multi-frame reassembly path: the First Frame declares `FF_DL` without a
cumulative bound check against the configured receive buffer). See
`../VERSIONS.md`.

One deviation from pristine: built with `STITCH_MULTIFRAME=0` so the receive
path matches the CVE call graph without re-sending. The vulnerable function is
upstream code, untouched by this flag.
