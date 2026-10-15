# Vendored library versions

Every library is vendored pristine from upstream and ships with its own LICENSE. The
three vulnerable libraries are unmaintained and have no upstream fix, so each is
vendored from the version the CVE record lists as affected (the "Vendored at" column
gives that commit or release). Each vulnerable entry also carries a one-line note on the
one deviation this benchmark makes (always a build-flag or a freestanding port, never a
change to the vulnerable function).

| Library | Upstream | Vendored at | CVE | Deviation |
|---|---|---|---|---|
| openxc/isotp-c | https://github.com/openxc/isotp-c | commit `5a5d1924` (affected, per CVE record; no upstream fix) | CVE-2026-37535 (receive-path OOB write; First Frame small FF_DL) | built with `STITCH_MULTIFRAME=0` (receive-only) |
| DanielMartensson/Open-SAE-J1939 | https://github.com/DanielMartensson/Open-SAE-J1939 | commit `b6caf884` (affected, per CVE record; no upstream fix) | CVE-2026-37534 (integer underflow -> OOB on `uint8_t[1785]`) | built with `-fsanitize=bounds` so the compiler's trap executes a precise `udf` |
| LiamBindle/MQTT-C | https://github.com/LiamBindle/MQTT-C | release `v1.1.6` (last affected, per CVE record; no upstream fix) | CVE-2026-54412 (OOB read on unbounded `topic_name_size`) | shipped with a freestanding `mqtt_pal.h` (no POSIX sockets); vulnerable function is untouched |
| zserge/jsmn | https://github.com/zserge/jsmn | current release | — (control) | none |
| kosma/minmea | https://github.com/kosma/minmea | current release | — (control) | none |
| jibsen/tinf | https://github.com/jibsen/tinf | current release | — (control) | none |

The vulnerable function in every CVE entry is upstream code; the deviation above does not
introduce the bug. In each `harness/app_*_hw.c` the header comment points at the exact
line of upstream code the trigger reaches.

## Device pack

pyocd supports the STM32F446 only through a CMSIS device pack, which is not vendored here.
`replay/devicepack.py` downloads **Keil.STM32F4xx_DFP 3.1.1** from Keil
(`https://www.keil.com/pack/Keil.STM32F4xx_DFP.3.1.1.pack`, 2,085,496 bytes) into `packs/` and
refuses it unless its SHA-256 is
`345231106fe697df24bbe9133aeeec1b0383d7891c4adf4f47bbb8b478e9f2f0`. The replay scripts load that
exact file, so they do not depend on pyocd's online pack index.
