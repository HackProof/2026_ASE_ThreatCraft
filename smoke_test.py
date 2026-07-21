#!/usr/bin/env python3

import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent

BACKEND = ROOT / "code" / "backend" / "parse_attack_graph_automotive.py"
EXAMPLE_DFD = ROOT / "example" / "Automotive_DFD.tm7"

LIBRARY_DIR = ROOT / "code" / "backend" / "threat_library"
AUTOMOTIVE_DIR = LIBRARY_DIR / "automotive"

ASSET_MAP = AUTOMOTIVE_DIR / "asset_to_threats_automotive.json"
THREAT_MAP = AUTOMOTIVE_DIR / "threat_to_tactic_automotive.json"
ATTACK_VECTOR_MAP = (
    AUTOMOTIVE_DIR / "attack_vector_feasibility_automotive.json"
)
IMPACT_MAP = AUTOMOTIVE_DIR / "impact_map_automotive.json"
DEPENDENCY_MAP = AUTOMOTIVE_DIR / "dependency_automotive.json"

OUTPUT_DIR = ROOT / "smoke_output"
OUTPUT_JSON = OUTPUT_DIR / "attack_graph.json"
OUTPUT_REPORT = OUTPUT_DIR / "attack_report.html"


def fail(message: str, details: str = "") -> None:
    print(f"[FAIL] {message}")

    if details:
        print()
        print(details.strip())

    sys.exit(1)


def main() -> None:
    print("ThreatCraft Smoke Test")
    print("=" * 40)

    # 1. Check Python version
    if sys.version_info < (3, 10):
        fail(
            "Python 3.10 or later is required.",
            f"Detected version: {sys.version}",
        )

    print(
        f"[PASS] Python version: "
        f"{sys.version_info.major}.{sys.version_info.minor}"
    )

    # 2. Check Graphviz
    dot_path = shutil.which("dot")

    if dot_path is None:
        fail(
            "Graphviz was not found.",
            "Install Graphviz and ensure that 'dot' is available in PATH.",
        )

    dot_result = subprocess.run(
        [dot_path, "-V"],
        capture_output=True,
        text=True,
    )

    graphviz_version = (
        dot_result.stderr.strip()
        or dot_result.stdout.strip()
        or "detected"
    )

    print(f"[PASS] Graphviz: {graphviz_version}")

    # 3. Check required files
    required_files = [
        BACKEND,
        EXAMPLE_DFD,
        ASSET_MAP,
        THREAT_MAP,
        ATTACK_VECTOR_MAP,
        IMPACT_MAP,
        DEPENDENCY_MAP,
    ]

    missing_files = [
        str(path.relative_to(ROOT))
        for path in required_files
        if not path.exists()
    ]

    if missing_files:
        fail(
            "Required artifact files are missing.",
            "\n".join(f"- {path}" for path in missing_files),
        )

    print("[PASS] Required input files found")

    # 4. Prepare output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for output_file in [OUTPUT_JSON, OUTPUT_REPORT]:
        if output_file.exists():
            output_file.unlink()

    # 5. Run the offline rule-based backend
    command = [
        sys.executable,
        str(BACKEND),
        "--tm7",
        str(EXAMPLE_DFD),
        "--type",
        "remote",
        "--target",
        "Door",
        "--boundary",
        "External Vehicle Boundary",
        "--asset-map",
        str(ASSET_MAP),
        "--threat-map",
        str(THREAT_MAP),
        "--attack-vector-map",
        str(ATTACK_VECTOR_MAP),
        "--impact-map",
        str(IMPACT_MAP),
        "--dependency-map",
        str(DEPENDENCY_MAP),
        "--out",
        str(OUTPUT_JSON),
        "--no-render-merged-graph",
        "--detection-report",
        str(OUTPUT_REPORT),
    ]

    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        details = "\n".join(
            part
            for part in [
                "Standard output:",
                result.stdout.strip(),
                "",
                "Standard error:",
                result.stderr.strip(),
            ]
            if part
        )

        fail("Rule-based backend execution failed.", details)

    print("[PASS] Rule-based backend completed")

    # 6. Validate generated JSON
    if not OUTPUT_JSON.exists():
        fail("The expected attack graph JSON file was not created.")

    try:
        with OUTPUT_JSON.open("r", encoding="utf-8") as file:
            output_data = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        fail("The generated output is not valid JSON.", str(error))

    nodes = output_data.get("nodes", [])
    paths = output_data.get("paths", [])

    if not nodes:
        fail("No attack graph nodes were generated.")

    if not paths:
        fail("No attack paths were generated.")

    print("[PASS] Output JSON created")
    print(f"[PASS] Attack graph nodes generated: {len(nodes)}")
    print(f"[PASS] Attack paths generated: {len(paths)}")
    print()
    print("SMOKE TEST PASSED")


if __name__ == "__main__":
    main()