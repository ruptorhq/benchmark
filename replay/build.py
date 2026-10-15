"""Compile one harness firmware for the STM32F446 and return the ELF path."""
import glob
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HARNESS = os.path.join(ROOT, "harness")
LIBS = os.path.join(ROOT, "libs")

GCC_EXE = "arm-none-eabi-gcc.exe" if os.name == "nt" else "arm-none-eabi-gcc"
GCC_HELP = ("arm-none-eabi-gcc not found. Install the Arm GNU Toolchain (developer.arm.com -> "
            "Arm GNU Toolchain Downloads -> arm-none-eabi), tick \"Add path to environment "
            "variable\" in the installer, then open a new terminal. If it is installed in a "
            "non-standard folder, set ARM_GCC to the folder that contains " + GCC_EXE + " and retry.")


def _windows_install_dirs():
    """Default Windows locations, most preferred first: Arm's own installer, then the copies ST bundles."""
    pf = [r for r in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")) if r]
    st = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "ST")
    return [
        [os.path.join(r, "Arm GNU Toolchain arm-none-eabi", "*", "bin") for r in pf],
        [os.path.join(st, "STM32CubeCLT*", "GNU-tools-for-STM32", "bin")],
        [os.path.join(st, "STM32CubeIDE*", "STM32CubeIDE", "plugins", "*gnu-tools-for-stm32*", "tools", "bin")],
        [os.path.join(r, "GNU Arm Embedded Toolchain", "*", "bin") for r in pf],
    ]


def find_gcc():
    """ARM_GCC if set, else PATH, else the toolchain's default Windows install folders."""
    override = os.environ.get("ARM_GCC")
    if override:
        if os.path.isdir(override):
            override = os.path.join(override, GCC_EXE)
        return override if os.path.isfile(override) else None
    gcc = shutil.which("arm-none-eabi-gcc")
    if gcc or os.name != "nt":
        return gcc
    for patterns in _windows_install_dirs():
        hits = [h for p in patterns for h in glob.glob(os.path.join(p, GCC_EXE))]
        if hits:
            return sorted(hits)[-1]
    return None


def build(app_name, bounds_checks=False):
    """Compile harness/<app_name>.c for the STM32F446 and return the ELF path.
    Fails loudly with gcc's own output.
    """
    gcc = find_gcc()
    if not gcc:
        sys.exit(GCC_HELP)
    out = os.path.join(HARNESS, f"{app_name}.elf")
    sanitizer = ["-fsanitize=bounds,object-size,signed-integer-overflow",
                 "-fsanitize-trap=undefined"] if bounds_checks else []
    cmd = [gcc,
           "-mcpu=cortex-m4", "-mthumb",
           "-nostdlib", "-nostartfiles", "-ffreestanding", "-fno-stack-protector",
           "-O1", "-g3", "-gdwarf-4",
           "-I", HARNESS,
           "-I", LIBS,
           "-I", os.path.join(LIBS, "isotp-c"),
           "-I", os.path.join(LIBS, "mqtt-c", "include"),
           "-T", os.path.join(HARNESS, "link_stm32f446.ld"),
           *sanitizer,
           "-DRUPTOR_SP=0x20020000u",
           os.path.join(HARNESS, f"{app_name}.c"),
           "-lgcc",
           "-o", out]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        tail = (result.stderr or "").strip().splitlines() or ["(no output)"]
        sys.exit("build failed:\n" + "\n".join(tail[-20:]))
    return out
