"""Run each Sigma rule against its attack log with Chainsaw and check it fires."""
import json
import subprocess
import sys

import yaml

CHAINSAW = "./chainsaw/chainsaw"
MAPPING = "./chainsaw/mappings/sigma-event-logs-all.yml"


def count_hits(rule, evtx):
    result = subprocess.run(
        [CHAINSAW, "hunt", evtx, "-s", rule, "--mapping", MAPPING, "--json", "-q"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(result.stderr)
        return -1
    out = result.stdout.strip()
    return len(json.loads(out)) if out else 0


def main():
    with open("tests.yml") as f:
        tests = yaml.safe_load(f)["tests"]

    rows, failed = [], 0
    for t in tests:
        hits = count_hits(t["rule"], t["evtx"])
        passed = hits >= 0 and (hits > 0) == t["expect_hits"]
        failed += not passed
        status = "✅ Caught" if passed else "❌ Missed"
        rows.append(f"| `{t['rule']}` | {t['technique']} | {hits} | {status} |")
        print(f"{status}: {t['rule']} ({hits} hits)")

    with open("results.md", "w") as f:
        f.write("| Rule | ATT&CK | Hits | Result |\n|---|---|---|---|\n")
        f.write("\n".join(rows) + "\n")

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
