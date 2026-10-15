"""T2 silicon validation for DanielMartensson/Open-SAE-J1939 CVE-2026-37534.
Built with UBSan trap on bounds (same deviation as how the fuzzer caught it on the model):
the integer-underflow out-of-bounds subscript executes a `udf` that is a real UsageFault
on the F446. Exits 0 on validated fault, 1 otherwise.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build import build
from devicepack import TARGET, session_options

RES = 0x20001000


def main():
    elf = build("app_j1939_hw", bounds_checks=True)
    from pyocd.core.helpers import ConnectHelper
    from pyocd.flash.file_programmer import FileProgrammer
    with ConnectHelper.session_with_chosen_probe(target_override=TARGET, connect_mode="under-reset",
                                                 **session_options()) as s:
        t = s.target
        t.reset_and_halt()
        FileProgrammer(s).program(elf, file_format="elf")
        t.reset_and_halt()
        t.resume()
        time.sleep(0.3)
        t.halt()
        magic, pc, cfsr = t.read32(RES), t.read32(RES + 4), t.read32(RES + 8)
    undefinstr = (cfsr >> 16) & 1
    ok = magic == 0x600D0000 and undefinstr
    print(f"finding      Open-SAE-J1939 CVE-2026-37534 (integer underflow -> OOB), repro TP.DT seq=0")
    print(f"magic        {magic:#010x}  ({'fault captured' if magic == 0x600D0000 else 'NO FAULT (bad)'})")
    print(f"CFSR         {cfsr:#010x}   UNDEFINSTR(bit16)={undefinstr}")
    print(f"faulting PC  {pc:#010x}  (the UBSan bounds-trap udf)")
    print("\nT2 VALIDATED -- the fuzzer-found OOB subscript faults the real F446 (UsageFault at the udf)" if ok
          else "\nNOT validated -- investigate")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
