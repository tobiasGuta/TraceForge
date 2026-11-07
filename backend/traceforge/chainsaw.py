"""Optional Chainsaw adapter. Runs a configured binary without a shell."""
import json
import os
from pathlib import Path
import shutil
import subprocess


def configuration() -> dict:
    executable = os.getenv("CHAINSAW_BIN", "chainsaw")
    resolved = shutil.which(executable)
    chain_rules = os.getenv("CHAINSAW_RULES_DIR", "")
    sigma_rules = os.getenv("SIGMA_RULES_DIR", "")
    mapping = os.getenv("CHAINSAW_MAPPING_FILE", "")
    configured = bool(chain_rules and Path(chain_rules).is_dir()) or bool(
        sigma_rules and mapping and Path(sigma_rules).is_dir() and Path(mapping).is_file()
    )
    return {
        "available": bool(resolved),
        "configured": configured,
        "chainsaw_rules": bool(chain_rules and Path(chain_rules).is_dir()),
        "sigma_rules": bool(sigma_rules and mapping and Path(sigma_rules).is_dir() and Path(mapping).is_file()),
    }


def hunt(paths: list[Path]) -> dict:
    conf = configuration()
    binary = shutil.which(os.getenv("CHAINSAW_BIN", "chainsaw"))
    if not binary:
        raise RuntimeError("Chainsaw executable not found. Configure CHAINSAW_BIN.")
    if not conf["configured"]:
        raise RuntimeError("Configure CHAINSAW_RULES_DIR or SIGMA_RULES_DIR plus CHAINSAW_MAPPING_FILE.")
    if not paths:
        raise RuntimeError("No successfully indexed EVTX files in this case.")
    command = [binary, "hunt", *map(str, paths)]
    if conf["chainsaw_rules"]:
        command.extend(["-r", os.environ["CHAINSAW_RULES_DIR"]])
    if conf["sigma_rules"]:
        command.extend(["-s", os.environ["SIGMA_RULES_DIR"],
                        "--mapping", os.environ["CHAINSAW_MAPPING_FILE"]])
    command.extend(["--json", "-q"])
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=120, check=False, shell=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Chainsaw exceeded the 120-second analysis limit.") from exc
    if result.returncode != 0:
        raise RuntimeError("Chainsaw returned an error: " + result.stderr[-1000:])
    if len(result.stdout) > 8_000_000:
        raise RuntimeError("Chainsaw output exceeds the 8 MB result limit.")
    try:
        detections = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        # Preserve the output instead of claiming it is normalized.
        detections = {"raw_output": result.stdout, "warning": "Unrecognized JSON output"}
    return {"engine": "chainsaw", "detections": detections,
            "stderr": result.stderr[-2000:]}
