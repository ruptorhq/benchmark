# Ruptor vulnerability benchmark

Real third-party embedded code, real public CVEs, reproduced on a real chip.
Everything here runs on a $15 NUCLEO-F446RE with its on-board ST-LINK.
Clone it, flash it, read the fault registers yourself.

## Results

| CVE | Library | Bug class | Found by the fuzzer, unaided | On the chip (STM32F446) |
|---|---|---|---|---|
| [CVE-2026-37535](https://nvd.nist.gov/vuln/detail/CVE-2026-37535) | openxc/isotp-c (ISO-TP over CAN) | out-of-bounds write on the receive path: a First Frame with a small FF_DL overruns the reassembly buffer (see the honesty note on this CVE's metadata) | yes, 52,589 runs, minimised to a 26-byte CAN frame stream | **MemManage fault.** CFSR DACCVIOL, MMFAR = guard base |
| [CVE-2026-37534](https://nvd.nist.gov/vuln/detail/CVE-2026-37534) | DanielMartensson/Open-SAE-J1939 | integer underflow, out-of-bounds subscript on `uint8_t[1785]` | yes, one TP.DT frame with sequence byte `00` | **UsageFault.** CFSR UNDEFINSTR, PC at the trap |
| [CVE-2026-54412](https://nvd.nist.gov/vuln/detail/CVE-2026-54412) | LiamBindle/MQTT-C | out-of-bounds read, unbounded `topic_name_size` | yes, 52,036 runs, minimised to 5 bytes (`2131040004`) | **MemManage fault.** CFSR DACCVIOL, MMFAR = guard base |

Controls, same pipeline, must come back clean: kosma/minmea, zserge/jsmn, jibsen/tinf.
All three: **no findings.**

## Reproduce the hardware result (10 minutes)

Hardware: NUCLEO-F446RE, USB cable.
Software: Python 3.11+, `arm-none-eabi-gcc` (Arm GNU Toolchain 13 or 14), `pyocd`.
Get the toolchain from developer.arm.com (Arm GNU Toolchain Downloads -> arm-none-eabi).
If it is not on PATH, the scripts also look in the default Windows install folders,
including the copy bundled with STM32CubeIDE / STM32CubeCLT under `C:\ST`. For any other
location, set `ARM_GCC` to the folder that contains `arm-none-eabi-gcc`. On Windows the
board may also need ST's ST-LINK USB driver (STSW-LINK009).

```
git clone https://github.com/ruptorhq/benchmark
cd benchmark
pip install -r requirements.txt
python replay/devicepack.py        # one time: pinned STM32F4 device pack (2 MB, SHA-256 checked)
python replay/preflight.py         # toolchain, modules, target, builds, probe
python replay/run_hw_isotp.py      # CVE-2026-37535
python replay/run_hw_j1939.py      # CVE-2026-37534
python replay/run_hw_mqtt.py       # CVE-2026-54412
```

Expected output for isotp-c:

```
finding      isotp-c CVE-2026-37535 (OOB write), repro First Frame FF_DL=2
guard (abuf_guard)  [0x20000080, 0x2000009f]  MPU no-access
magic        0x600d0000  (MemManage captured)
CFSR         0x00000082   DACCVIOL(bit1)=1  MMARVALID(bit7)=1
MMFAR        0x20000080   in guard=True
faulting PC  0x08000132

T2 VALIDATED -- the fuzzer-found OOB faults precisely at the guard on real F446 silicon
```

What the script does: builds the harness firmware with the vulnerable library vendored
pristine, flashes it over ST-LINK, lets the firmware feed the minimised trigger to the
library's own receive path, then reads PC, CFSR and MMFAR back over SWD. The guard after
the receive buffer is an MPU no-access region, so a one-byte overflow becomes a precise
MemManage fault instead of silent corruption.

## What is and is not in this repo

- **In:** the three vulnerable libraries at their CVE versions, pristine (the one
  deviation per library is documented in each harness header); the three control
  libraries; the harness firmware (`harness/app_isotp_hw.c`, `app_j1939_hw.c`,
  `app_mqtt_hw.c`); the minimised triggers; the replay scripts; the F446 MPU
  ground-truth file (`board/nucleo_f446re_mpu.json`).
- **Not in:** the fuzzer, the peripheral capture, the chip models. How the trigger was
  found is Ruptor; that it is real is this repo.

## Honesty notes

- The CAN CVEs are delivered inside the harness, not over the board's physical CAN bus.
  Replay asserts that the chip faults on the library's own code path with the fuzzer's
  input; bus delivery is tracked separately.
- The CAN peripheral model used for fuzzing is derived from STM32 documentation (RM0390);
  USART is captured from silicon.
- A clean control is "no indication within the fuzzed coverage", never a proof of security.
- CVE-2026-37535's public metadata is inconsistent: the NVD summary reads it as a
  single-frame out-of-bounds read (CWE-125), while the reporter's referenced writeup
  describes an unchecked length on the ISO-TP multi-frame reassembly path. This
  benchmark documents the fault it actually reproduces on silicon -- an out-of-bounds
  write when a First Frame declares a small FF_DL -- and leaves the exact
  classification to the reader. The hardware harness replays a reduced single-frame
  trigger; the 26-byte figure is the fuzzer's minimised campaign input.

## Adding an entry

Pick a library at a version with a documented memory bug on the parse or receive path,
prefer malloc-free, vendor it pristine, write a harness that feeds input over the
library's own receive path, add the minimised trigger and the expected fault registers.
Pull requests with a new CVE and a passing replay are welcome.

License: Apache-2.0 for the harnesses and scripts. Vendored libraries keep their own
licenses.
