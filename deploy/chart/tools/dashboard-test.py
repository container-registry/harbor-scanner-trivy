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
        for panel in DASHBOARD["panels"]:
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
        for panel in DASHBOARD["panels"]:
            self.assertNotIn(panel["id"], ids)
            ids.add(panel["id"])
            pos = panel["gridPos"]
            for x in range(pos["x"], pos["x"] + pos["w"]):
                self.assertLess(x, 24)
                for y in range(pos["y"], pos["y"] + pos["h"]):
                    self.assertNotIn((x, y), occupied, panel["title"])
                    occupied.add((x, y))


if __name__ == "__main__":
    unittest.main()
