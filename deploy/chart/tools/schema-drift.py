#!/usr/bin/env python3
"""Two-way drift check between values.yaml and values.schema.json.

`helm lint` validates values against the schema, but only where the schema
actually declares a property. It cannot see the two failure modes this catches:

  [unvalidated] a values.yaml key the schema is silent about - no type check,
                no IDE completion, and at the closed root it breaks every render
  [dead]        a schema property with no values.yaml counterpart - advertised
                to users but never rendered by any template

Acknowledged drift goes in .schema-drift-allow, one `[kind] path` per line,
each with a comment saying why.

Usage: tools/schema-drift.py values.yaml values.schema.json [.schema-drift-allow]
"""

import json
import sys

import yaml

# A schema node that declares no `properties` is a deliberate free-form
# passthrough (podSecurityContext, resources, a probe spec); its children are
# the user's business, not the chart's.
def walk(values, schema, path, findings):
    props = schema.get("properties")
    if not isinstance(props, dict):
        return

    if isinstance(values, dict):
        for key, child in values.items():
            here = f"{path}.{key}" if path else key
            if key not in props:
                findings.append(("unvalidated", here))
                continue
            walk(child, unwrap(props[key]), here, findings)

    for key, subschema in props.items():
        here = f"{path}.{key}" if path else key
        if not isinstance(values, dict) or key not in values:
            findings.append(("dead", here))


# anyOf/oneOf wrappers exist to allow null or a union; drift only cares about
# the object branch that carries properties.
def unwrap(node):
    if "properties" in node:
        return node
    # allOf is a conjunction: properties can be split across branches and all of
    # them apply, so taking the first would report later ones as drift.
    merged = {}
    for branch in node.get("allOf", []):
        if isinstance(branch, dict) and "properties" in branch:
            merged.update(branch["properties"])
    if merged:
        return {"properties": merged}
    # anyOf/oneOf branches are alternatives, usually "this shape or null"; the
    # object branch is the only one with properties to walk.
    for combinator in ("anyOf", "oneOf"):
        for branch in node.get(combinator, []):
            if isinstance(branch, dict) and "properties" in branch:
                return branch
    return node


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2

    values = yaml.safe_load(open(argv[1])) or {}
    schema = json.load(open(argv[2]))
    allow_path = argv[3] if len(argv) > 3 else None

    allowed = set()
    if allow_path:
        try:
            for line in open(allow_path):
                line = line.split("#", 1)[0].strip()
                if line:
                    allowed.add(line)
        except FileNotFoundError:
            pass

    findings = []
    walk(values, schema, "", findings)

    unexpected = [f for f in findings if f"[{f[0]}] {f[1]}" not in allowed]
    for kind, path in sorted(unexpected, key=lambda f: (f[0], f[1])):
        print(f"[{kind}] {path}", file=sys.stderr)

    if unexpected:
        print(
            f"\n{len(unexpected)} schema drift finding(s). Fix values.schema.json or "
            f"values.yaml, or record the drift with a reason in .schema-drift-allow.",
            file=sys.stderr,
        )
        return 1

    print("values.yaml and values.schema.json agree")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
