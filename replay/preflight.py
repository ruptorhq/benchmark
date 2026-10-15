"""Preflight check for the benchmark.

Verifies that your machine has what the three replay scripts need:
  * arm-none-eabi-gcc (ARM_GCC if set, else PATH, else its default Windows install folders,
    including the copy bundled with STM32CubeIDE / STM32CubeCLT)
  * python modules: pyocd, elftools
  * a connected NUCLEO-F446RE probe (ST-LINK)
  * each of the three harness ELFs can be built from the public tree

Exits non-zero on the first failure, so this is safe to drop into CI.
"""
import importlib
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build


def ok(msg):
    print(f"[ ok ] {msg}")


def fail(msg):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def check_toolchain():
    gcc = build.find_gcc()
    if not gcc:
        fail(build.GCC_HELP)
    try:
        out = subprocess.run([gcc, "--version"], capture_output=True, text=True, check=True)
        first = (out.stdout or "").splitlines()[0] if out.stdout else "(no version string)"
        if os.environ.get("ARM_GCC"):
            where = f"  (from ARM_GCC: {os.path.dirname(gcc)})"
        elif shutil.which("arm-none-eabi-gcc"):
            where = ""
        else:
            where = f"  (not on PATH; using {os.path.dirname(gcc)})"
        ok(f"arm-none-eabi-gcc: {first}{where}")
    except subprocess.CalledProcessError as e:
        fail(f"arm-none-eabi-gcc failed to run: {e}")


def check_python_mods():
    for mod, pip_name in [("pyocd", "pyocd>=0.36"), ("elftools", "pyelftools>=0.29")]:
        try:
            importlib.import_module(mod)
            ok(f"python module: {mod}")
        except ImportError:
            fail(f"python module '{mod}' not importable. Run: pip install {pip_name}")


def check_probe():
    from pyocd.core.helpers import ConnectHelper
    probes = ConnectHelper.get_all_connected_probes(blocking=False)
    if not probes:
        fail("no SWD probe detected. Plug in the NUCLEO-F446RE over USB and retry. On Windows, "
             "if the board is plugged in but not detected, install ST's ST-LINK USB driver "
             "(STSW-LINK009) and replug.")
    for p in probes:
        ok(f"probe: {p.vendor_name} {p.product_name} ({p.unique_id})")


def check_builds():
    for app, flag in [("app_isotp_hw", False), ("app_j1939_hw", True), ("app_mqtt_hw", False)]:
        try:
            elf = build.build(app, bounds_checks=flag)
            size_kb = os.path.getsize(elf) / 1024
            ok(f"build {app}: {size_kb:.1f} KB")
        except SystemExit as e:
            fail(f"build {app}: {e}")


def main():
    print("Preflight check for the vuln-benchmark replay pipeline.")
    print(f"python: {sys.version.split()[0]} ({sys.executable})")
    print("-" * 60)
    check_toolchain()
    check_python_mods()
    check_builds()
    check_probe()
    print("-" * 60)
    print("All preflight checks passed. You are ready to run the three replay scripts.")


if __name__ == "__main__":
    main()
