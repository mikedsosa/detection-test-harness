"""Write rules/PROVENANCE.json: the source and SHA-256 of every vendored rule file."""

import hashlib
import json

from dth.rules import REGISTRY, RULES

out = {}
for rule in REGISTRY:
    for rel, path in zip(rule.files, rule.paths, strict=True):
        out[rel] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "source": rule.source.removesuffix(", adapted"),
            "owner": rule.owner,
        }
(RULES / "PROVENANCE.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"recorded {len(out)} files")
