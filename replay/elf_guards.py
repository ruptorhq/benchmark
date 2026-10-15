"""elf_guards: discover MPU guard ranges from an ELF symbol table.

Every OBJECT symbol whose name ends `suffix` is a guarded buffer (see harness/board.h
RB_GUARD) laid out as [buffer][RB_RZ_SZ guard]; its last `rz_size` bytes are the guard.
Returns [(lo, hi_inclusive, name)]. Nothing is hard-coded -- the ranges come straight
from where the linker placed each guarded object.
"""
from elftools.elf.elffile import ELFFile


def elf_redzones(path, rz_size, suffix="_guard"):
    out = []
    with open(path, "rb") as f:
        st = ELFFile(f).get_section_by_name(".symtab")
        if st is None:
            return out
        for s in st.iter_symbols():
            if (s.name.endswith(suffix) and s["st_info"]["type"] == "STT_OBJECT"
                    and s["st_size"] > rz_size and s["st_value"]):
                base, size = s["st_value"], s["st_size"]
                out.append((base + size - rz_size, base + size - 1, s.name))
    return out
