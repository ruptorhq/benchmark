# MQTT-C

Upstream: https://github.com/LiamBindle/MQTT-C
License: MIT (SPDX: MIT) — Copyright (c) 2018 Liam Bindle. See the header
of `include/mqtt.h` for the full license text.

Vendored at the pre-fix commit for CVE-2026-54412 (out-of-bounds read in the
PUBLISH decoder on an unbounded `topic_name_size`). See `../VERSIONS.md`.

One deviation from pristine: a freestanding `include/mqtt_pal.h` replaces the
default POSIX-sockets PAL, so the library can run on bare-metal Cortex-M in
this benchmark. The vulnerable function (`mqtt_unpack_publish_response`) is
upstream code, untouched by this deviation.
