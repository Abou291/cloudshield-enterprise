"""Extract exact runtime dependencies from a successful pip JSON report."""
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
requirements = [
    f"{item['metadata']['name']}=={item['metadata']['version']}"
    for item in report["install"]
    if item["metadata"]["name"].replace("_", "-").lower() != "aegisshield-api"
]
if not requirements:
    raise ValueError("Refusing to audit an empty dependency set")
Path(sys.argv[2]).write_text("\n".join(requirements) + "\n", encoding="utf-8")
