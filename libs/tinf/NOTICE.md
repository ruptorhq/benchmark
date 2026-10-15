# tinf

Upstream: https://github.com/jibsen/tinf
License: zlib (SPDX: Zlib) — Copyright (c) 2003-2019 Joergen Ibsen. See the
header of `tinf.h` for the full license text.

Vendored pristine. No modifications. Used in this benchmark as a clean control:
a tiny-footprint inflate / gzip / zlib decoder that the fuzzer, applied with
the same pipeline that found the three CVEs in the vulnerable libraries,
returns no findings on.
