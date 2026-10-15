"""T2 silicon validation for LiamBindle/MQTT-C CVE-2026-54412.
Replays the minimised PUBLISH (remaining_length=4, topic_name_size=5) on a NUCLEO-F446RE
with the receive buffer's guard mapped MPU no-access, and confirms the OOB read faults at
the guard. Exits 0 on validated fault, 1 otherwise.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build import build
from elf_guards import elf_redzones

RES = 0x20001000


def main():
    elf = build("app_mqtt_hw")
    guard_lo, guard_hi, gname = elf_redzones(elf, 32)[0]
    from pyocd.core.helpers import ConnectHelper
    from pyocd.flash.file_programmer import FileProgrammer
    with ConnectHelper.session_with_chosen_probe(target_override="stm32f446retx",
                                                 connect_mode="under-reset") as s:
        t = s.target
        t.reset_and_halt()
        FileProgrammer(s).program(elf, file_format="elf")
        t.reset_and_halt()
        t.resume()
        time.sleep(0.3)
        t.halt()
        magic, pc, mmfar, cfsr = (t.read32(RES + 4 * i) for i in range(4))
    daccviol, mmarvalid = (cfsr >> 1) & 1, (cfsr >> 7) & 1
    in_guard = guard_lo <= mmfar <= guard_hi
    ok = magic == 0x600D0000 and daccviol and in_guard
    print(f"finding      LiamBindle/MQTT-C CVE-2026-54412 (OOB read), repro PUBLISH remaining_length=4 topic_name_size=5")
    print(f"guard ({gname})  [{guard_lo:#010x}, {guard_hi:#010x}]  MPU no-access")
    print(f"magic        {magic:#010x}  ({'MemManage captured' if magic == 0x600D0000 else 'NO FAULT (bad)'})")
    print(f"CFSR         {cfsr:#010x}   DACCVIOL(bit1)={daccviol}  MMARVALID(bit7)={mmarvalid}")
    print(f"MMFAR        {mmfar:#010x}   in guard={in_guard}")
    print(f"faulting PC  {pc:#010x}")
    print("\nT2 VALIDATED -- the fuzzer-found OOB read faults precisely at the guard on real F446 silicon" if ok
          else "\nNOT validated -- investigate")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
