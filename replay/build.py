"""Compile one harness firmware for the STM32F446 and return the ELF path."""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
HARNESS = os.path.join(ROOT, "harness")
LIBS = os.path.join(ROOT, "libs")


def build(app_name, bounds_checks=False):
    """Compile harness/<app_name>.c for the STM32F446 and return the ELF path.
    Fails loudly with gcc's own output.
    """
    gcc = shutil.which("arm-none-eabi-gcc")
    if not gcc:
        sys.exit("arm-none-eabi-gcc not found on PATH. Install the Arm GNU Toolchain and retry.")
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
