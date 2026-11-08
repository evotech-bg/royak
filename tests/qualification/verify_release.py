"""Verify a built release, not production readiness; never invoke Docker or deploy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile


MAX_BYTES = 10 * 1024 * 1024


def binary_identity(header, system, machine):
    arch = {"arm64": "ARM64", "aarch64": "ARM64", "x86_64": "X64",
            "amd64": "X64"}.get(machine.lower())
    if arch is None:
        raise ValueError(f"Unsupported runner architecture: {machine}")
    if system == "Linux":
        if header[:7] != b"\x7fELF\x02\x01\x01" or len(header) < 20:
            raise ValueError("Expected a little-endian ELF64 release")
        if int.from_bytes(header[18:20], "little") != {"X64": 62, "ARM64": 183}[arch]:
            raise ValueError("ELF architecture does not match the runner")
    elif system == "Darwin":
        if header[:4] != b"\xcf\xfa\xed\xfe" or len(header) < 8:
            raise ValueError("Expected a little-endian 64-bit Mach-O release")
        if int.from_bytes(header[4:8], "little") != {"X64": 0x1000007, "ARM64": 0x100000c}[arch]:
            raise ValueError("Mach-O architecture does not match the runner")
    else:
        raise ValueError(f"Unsupported runner OS: {system}")
    return arch


def verify(binary, report_path, *, system=None, machine=None):
    report = {"passed": False, "production_qualified": False,
              "commit": os.environ.get("GITHUB_SHA"), "checks": []}
    try:
        binary = binary.resolve(strict=True)
        data = binary.read_bytes()
        report.update(binary=str(binary), bytes=len(data),
                      sha256=hashlib.sha256(data).hexdigest())
        if not 0 < len(data) <= MAX_BYTES:
            raise ValueError("Release exceeds the unchanged 10 MiB gate, or is empty")
        report["arch"] = binary_identity(data[:32], system or platform.system(),
                                          machine or platform.machine())
        # Brain writes weights; neither a previous checkout's weights nor state
        # may affect the smoke, and no smoke output may pollute the checkout.
        with tempfile.TemporaryDirectory(prefix="royak-release-smoke-") as directory:
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("ROYAK_")}
            env.update(HOME=directory, ROYAK_STATE=str(Path(directory) / "state.json"))
            for command, pattern in (("brain", r"OrinBrain"),
                                     ("demo", r"SCHEDULE|Noop|SCALE")):
                result = subprocess.run([str(binary), command], cwd=directory,
                                        env=env, capture_output=True, text=True,
                                        timeout=90, check=False)
                check = {"command": command, "exit_code": result.returncode,
                         "stdout": result.stdout, "stderr": result.stderr}
                report["checks"].append(check)
                if result.returncode != 0:
                    raise ValueError(f"{command} failed with exit code {result.returncode}")
                if re.search(pattern, result.stdout + result.stderr) is None:
                    raise ValueError(f"{command} produced no expected smoke marker")
        if hashlib.sha256(binary.read_bytes()).hexdigest() != report["sha256"]:
            raise ValueError("Release binary changed during verification")
        report["passed"] = True
    except Exception as error:
        report["failure"] = f"{type(error).__name__}: {error}"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.binary, args.report)
    print(json.dumps({key: value for key, value in result.items() if key != "checks"}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
