# Clean-room run logs

Paste the exact console output of each replay script here, including the toolchain and
pyocd versions, when running from a fresh clone on a NUCLEO-F446RE.

A reference run from the project maintainers is kept first so a downstream clean-room
run has a concrete baseline to compare against. Add your own run below it; don't
overwrite the reference.

---

## Reference run (project maintainers)

Date: 2026-10-14
Host: Windows 10 Pro, Python 3.10.7
Toolchain:

```
arm-none-eabi-gcc.exe (Arm GNU Toolchain 14.2.Rel1 (Build arm-14.52)) 14.2.1 20241119
pyocd 0.45.1
```

Probe: NUCLEO-F446RE on-board ST-LINK.

### isotp-c · CVE-2026-37535

```
finding      isotp-c CVE-2026-37535 (OOB write), repro First Frame FF_DL=2
guard (abuf_guard)  [0x20000080, 0x2000009f]  MPU no-access
magic        0x600d0000  (MemManage captured)
CFSR         0x00000082   DACCVIOL(bit1)=1  MMARVALID(bit7)=1
MMFAR        0x20000080   in guard=True
faulting PC  0x08000132

T2 VALIDATED -- the fuzzer-found OOB faults precisely at the guard on real F446 silicon
```

### Open-SAE-J1939 · CVE-2026-37534

```
finding      Open-SAE-J1939 CVE-2026-37534 (integer underflow -> OOB), repro TP.DT seq=0
magic        0x600d0000  (fault captured)
CFSR         0x00010000   UNDEFINSTR(bit16)=1
faulting PC  0x080001b8  (the UBSan bounds-trap udf)

T2 VALIDATED -- the fuzzer-found OOB subscript faults the real F446 (UsageFault at the udf)
```

### MQTT-C · CVE-2026-54412

```
finding      LiamBindle/MQTT-C CVE-2026-54412 (OOB read), repro PUBLISH remaining_length=4 topic_name_size=5
guard (rxbuf_guard)  [0x20000040, 0x2000005f]  MPU no-access
magic        0x600d0000  (MemManage captured)
CFSR         0x00000082   DACCVIOL(bit1)=1  MMARVALID(bit7)=1
MMFAR        0x20000040   in guard=True
faulting PC  0x08000a58

T2 VALIDATED -- the fuzzer-found OOB read faults precisely at the guard on real F446 silicon
```

---

## Clean-room runs (yours)

Add your clean-room run below with your toolchain versions. Do not tune the harness to
make it pass; if it does not reproduce, write what happened here and open an issue.

### Your toolchain

```
arm-none-eabi-gcc --version
pyocd --version
python --version
```

### isotp-c · CVE-2026-37535

```
# python replay/run_hw_isotp.py
<paste output here>
```

### Open-SAE-J1939 · CVE-2026-37534

```
# python replay/run_hw_j1939.py
<paste output here>
```

### MQTT-C · CVE-2026-54412

```
# python replay/run_hw_mqtt.py
<paste output here>
```
