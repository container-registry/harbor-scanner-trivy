#!/usr/bin/env python3
"""Check dashboard provisioning and isolation contracts without a Grafana server."""

import json
from pathlib import Path
import re
import subprocess
import unittest

import yaml

CHART = Path(__file__).resolve().parents[1]
DASHBOARD = json.loads((CHART / "dashboards/trivy.json").read_text())


def all_panels(panels=None):
    for panel in DASHBOARD["panels"] if panels is None else panels:
        yield panel
        yield from all_panels(panel.get("panels", []))


class DashboardTest(unittest.TestCase):
    def test_render_preserves_canonical_json(self):
        output = subprocess.check_output(
            ["helm", "template", "test", str(CHART), "--set",
             "metrics.grafanaDashboard.enabled=true"], text=True,
        )
        dashboards = [d["data"]["harbor-trivy-scanner.json"]
                      for d in yaml.safe_load_all(output)
                      if d and "harbor-trivy-scanner.json" in d.get("data", {})]
        self.assertEqual(len(dashboards), 1)
        self.assertEqual(json.loads(dashboards[0]), DASHBOARD)

    def test_installation_selectors_cannot_aggregate(self):
        variables = {v["name"]: v for v in DASHBOARD["templating"]["list"]}
        for name in ("cluster", "namespace", "scanner"):
            variable = variables[name]
            self.assertFalse(variable["multi"])
            self.assertFalse(variable["includeAll"])
            self.assertEqual(variable["current"], {})
            self.assertEqual(variable["sort"], 1)
        for name in ("namespace", "scanner", "scanner_pods"):
            self.assertIn('${cluster:regex}', str(variables[name]["query"]))
        for name in ("scanner", "scanner_pods"):
            self.assertIn('${namespace:regex}', str(variables[name]["query"]))
        self.assertIn('${scanner:regex}', str(variables["scanner_pods"]["query"]))
        # All here means the explicit discovered pod list, never a wildcard.
        self.assertFalse(variables["scanner_pods"].get("allValue"))
        self.assertEqual(variables["scanner_pods"]["hide"], 2)

    def test_queries_keep_selected_scope_and_use_known_metrics(self):
        catalog = (CHART.parents[1] / "pkg/metrics/recorder.go").read_text()
        known = set(re.findall(r'\{"([a-z_]+)",', catalog))
        known.update(re.findall(r'Name: Prefix \+ "([a-z_]+)"', catalog))
        redis = (CHART.parents[1] / "pkg/metrics/redis.go").read_text()
        known.update(re.findall(r'add\("([a-z_]+)"', redis))
        for panel in all_panels():
            if panel["type"] == "text":
                continue
            for target in panel.get("targets", []):
                expr = target["expr"]
                with self.subTest(panel=panel["title"]):
                    self.assertIn('cluster=~"${cluster:regex}"', expr)
                    self.assertIn('namespace=~"${namespace:regex}"', expr)
                    for name, labels in re.findall(
                        r'harbor_scanner_trivy_([a-z_]+)\{([^}]+)\}',
                        # Remove variable braces so the metric selector can be read.
                        re.sub(r'\$\{(\w+):regex\}', r'VARIABLE_\1', expr),
                    ):
                        base = re.sub(r'_(bucket|sum|count)$', '', name)
                        self.assertIn(base, known)
                        self.assertIn('scanner=~"VARIABLE_scanner"', labels)
                    if 'container_' in expr:
                        self.assertIn('and on (cluster,namespace,pod)', expr)
                        self.assertIn('scanner=~"${scanner:regex}"', expr)
                    if panel["type"] == "logs":
                        self.assertIn('pod=~"${scanner_pods:regex}"', expr)
                        self.assertIn('pod!=""', expr)
                    if 'redis_memory_used_bytes' in expr:
                        self.assertIn('service!=""', expr)
                        self.assertIn('${redis_service:regex}', expr)

    def test_runtime_follows_overview_and_panels_do_not_overlap(self):
        rows = [p for p in DASHBOARD["panels"] if p["type"] == "row"]
        self.assertEqual([p["title"] for p in rows[:2]], ["Overview", "Runtime"])
        occupied = set()
        ids = set()
        for panel in all_panels():
            self.assertNotIn(panel["id"], ids)
            ids.add(panel["id"])
            pos = panel["gridPos"]
            for x in range(pos["x"], pos["x"] + pos["w"]):
                self.assertLess(x, 24)
                for y in range(pos["y"], pos["y"] + pos["h"]):
                    self.assertNotIn((x, y), occupied, panel["title"])
                    occupied.add((x, y))

    def test_database_rows_isolate_data_and_share_collection_health(self):
        sections = {}
        current = None
        for panel in DASHBOARD["panels"]:
            if panel["type"] == "row":
                current = panel["title"]
                sections[current] = []
                if current in ("Vulnerability database", "Java package index"):
                    self.assertFalse(panel["collapsed"])
            elif current:
                sections[current].append(panel)
        names = list(sections)
        self.assertEqual(names.index("Java package index"),
                         names.index("Vulnerability database") + 1)
        for section, database in (("Vulnerability database", "vulnerability"),
                                  ("Java package index", "java")):
            panels = sections[section]
            self.assertEqual(len(panels), 5)
            for panel in panels:
                for target in panel["targets"]:
                    self.assertIn(f'database="{database}"', target["expr"])
                    self.assertNotIn("sum(", target["expr"])
        for metric in ("metadata_collection_success",
                       "metadata_last_success_timestamp_seconds"):
            owners = [name for name, panels in sections.items()
                      for panel in panels for target in panel.get("targets", [])
                      if "harbor_scanner_trivy_" + metric in target["expr"]]
            self.assertEqual(owners, ["Database monitoring health"])

    def test_current_database_status_has_unknown_and_history(self):
        panels = {panel["id"]: panel for panel in all_panels()}
        for pid in (32, 34, 70, 72):
            panel = panels[pid]
            self.assertEqual(panel["type"], "stat")
            self.assertEqual(panel["options"]["graphMode"], "none")
            for target in panel["targets"]:
                self.assertTrue(target["instant"])
                self.assertFalse(target["range"])
                self.assertIn(" == 1", target["expr"])
                self.assertIn(" * 0 - 1", target["expr"])
            states = panel["fieldConfig"]["defaults"]["mappings"][0]["options"]
            self.assertEqual(states["-1"]["text"], "Unknown")
            history_id = int(re.search(r"viewPanel=(\d+)", panel["links"][-1]["url"]).group(1))
            self.assertTrue(panels[history_id]["targets"][0]["range"])

    def test_status_views_have_consistent_dimensions_and_order(self):
        panels = {panel["id"]: panel for panel in all_panels()}
        for panel in panels.values():
            if panel["type"] == "state-timeline" and panel["id"] != 35:
                self.assertEqual((panel["gridPos"]["w"], panel["gridPos"]["h"]),
                                 (6, 7 if panel["id"] == 60 else 3))
                self.assertEqual(panel["gridPos"]["x"], 0)
        for pid in (35, 36):
            self.assertEqual((panels[pid]["gridPos"]["w"], panels[pid]["gridPos"]["h"]), (12, 7))
        for ids in ((32, 34, 31, 92, 33), (70, 72, 69, 93, 71)):
            positions = [panels[pid]["gridPos"] for pid in ids]
            self.assertEqual(len({p["y"] for p in positions}), 1)
            self.assertEqual([p["h"] for p in positions], [3] * 5)
            self.assertEqual(positions[0]["x"], 0)
            self.assertEqual(sum(p["w"] for p in positions), 24)
            for left, right in zip(positions, positions[1:]):
                self.assertEqual(left["x"] + left["w"], right["x"])
        for availability, policy in ((85, 86), (88, 89)):
            a, b = panels[availability]["gridPos"], panels[policy]["gridPos"]
            self.assertEqual((a["w"], a["h"]), (6, 3))
            self.assertEqual((b["w"], b["h"]), (6, 3))
            self.assertEqual(a["x"], b["x"])
            self.assertEqual(a["y"] + a["h"], b["y"])


if __name__ == "__main__":
    unittest.main()
