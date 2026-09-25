"""Generate language-agnostic JSON-Schema contracts from the Vantage domain models.

These schemas are the interoperability boundary: components in any language (the
Go egress proxy, a TypeScript UI/SDK, external integrations) consume the same
versioned contract that the Python control plane produces. Run:

    python scripts/gen_contracts.py

and commit the result under contracts/.
"""

from __future__ import annotations

import json
from pathlib import Path

from vantage import __version__
from vantage.domain import (
    EngineRunRequest,
    Evidence,
    Observation,
    ScopeRule,
    Target,
    UnifiedFinding,
)

OUT = Path("contracts")
MODELS = {
    "scope-rule": ScopeRule,
    "target": Target,
    "engine-run-request": EngineRunRequest,
    "evidence": Evidence,
    "observation": Observation,
    "unified-finding": UnifiedFinding,
}


def main() -> None:
    OUT.mkdir(exist_ok=True)
    index = {"version": __version__, "schemas": []}
    for name, model in MODELS.items():
        schema = model.model_json_schema()
        schema["$id"] = f"https://vantage.example/contracts/{name}.schema.json"
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["x-vantage-version"] = __version__
        path = OUT / f"{name}.schema.json"
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        index["schemas"].append({"name": name, "file": path.name, "title": schema.get("title", name)})
        print(f"wrote {path}")
    (OUT / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
