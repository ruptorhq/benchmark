# Open-SAE-J1939

Upstream: https://github.com/DanielMartensson/Open-SAE-J1939
License: MIT (SPDX: MIT) — Copyright (c) 2021 Daniel Mårtensson. The full
license text is in the `LICENSE` file in this folder, vendored verbatim from
upstream.

Vendored at the pre-fix commit for CVE-2026-37534 (integer underflow in the
TP.CM / TP.DT reassembly producing an out-of-bounds subscript on
`uint8_t[1785]`). See `../VERSIONS.md`.

One deviation from pristine: built with `-fsanitize=bounds` and
`-fsanitize-trap=undefined`, so the compiler-inserted bounds check executes a
precise `udf` on the OOB index, which the firmware traps as a UsageFault with
`CFSR.UNDEFINSTR=1`. The vulnerable function is upstream code, untouched by
these flags.
