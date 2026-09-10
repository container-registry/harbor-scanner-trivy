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
VALKEY = json.loads((CHART / "dashboards/valkey.json").read_text())


def all_panels(panels=None):
    for panel in DASHBOARD["panels"] if panels is None else panels:
        yield panel
        yield from all_panels(panel.get("panels", []))


def assert_harbor_scope(test, expr):
    # Variable braces must not terminate the surrounding PromQL selector.
    expr = re.sub(r'\$\{(\w+):regex\}', r'VARIABLE_\1', expr)
    for metric, labels in re.findall(r'\b(harbor_[a-z_]+)(?:\{([^}]*)\})?', expr):
        for label in ("cluster", "namespace"):
            test.assertIn(f'{label}=~"VARIABLE_{label}"', labels, metric)


def assert_layout(test, panels, ids=None):
    # Collapsed rows have a separate layout; IDs remain unique dashboard-wide.
    if ids is None:
        ids = set()
    occupied = set()
    for panel in panels:
        test.assertNotIn(panel["id"], ids)
        ids.add(panel["id"])
        pos = panel["gridPos"]
        test.assertGreaterEqual(pos["x"], 0, panel["title"])
        test.assertGreaterEqual(pos["y"], 0, panel["title"])
        test.assertGreater(pos["w"], 0, panel["title"])
        test.assertGreater(pos["h"], 0, panel["title"])
        test.assertLessEqual(pos["x"] + pos["w"], 24, panel["title"])
        for x in range(pos["x"], pos["x"] + pos["w"]):
            for y in range(pos["y"], pos["y"] + pos["h"]):
                test.assertNotIn((x, y), occupied, panel["title"])
                occupied.add((x, y))
        assert_layout(test, panel.get("panels", []), ids)


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
        valkey = [d["data"]["harbor-valkey.json"]
                  for d in yaml.safe_load_all(output)
                  if d and "harbor-valkey.json" in d.get("data", {})]
        self.assertEqual(len(valkey), 1)
        self.assertEqual(json.loads(valkey[0]), VALKEY)

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
                    assert_harbor_scope(self, expr)
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
        assert_layout(self, DASHBOARD["panels"])

    def test_scope_check_rejects_labels_from_another_vector(self):
        scope = 'cluster=~"${cluster:regex}",namespace=~"${namespace:regex}"'
        for metric in ('harbor_task_queue_size', 'harbor_task_queue_size{type="IMAGE_SCAN"}'):
            with self.subTest(metric=metric), self.assertRaises(AssertionError):
                assert_harbor_scope(self, metric + ' + up{' + scope + '}')

    def test_database_rows_isolate_data_and_share_collection_health(self):
        sections = {}
        current = None
        for panel in DASHBOARD["panels"]:
            if panel["type"] == "row":
                current = panel["title"]
                sections[current] = list(panel.get("panels", []))
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
            self.assertEqual(len(panels), 1)
            self.assertEqual(panels[0]["type"], "table")
            self.assertEqual(len(panels[0]["targets"]), 5)
            for panel in panels:
                for target in panel["targets"]:
                    self.assertIn(f'database="{database}"', target["expr"])
                    self.assertNotIn("sum(", target["expr"])
        for metric in ("metadata_collection_success",
                       "metadata_last_success_timestamp_seconds"):
            owners = [name for name, panels in sections.items()
                      for panel in panels for target in panel.get("targets", [])
                      if "harbor_scanner_trivy_" + metric in target["expr"]]
            self.assertEqual(owners, ["Monitoring diagnostics"])

    def test_analysis_cache_is_filtered_by_reported_backend(self):
        panels = {panel["id"]: panel for panel in all_panels()}
        local = panels[99]["targets"][0]["expr"]
        self.assertIn('kind="analysis"', local)
        self.assertIn('analysis_cache_backend_info', local)
        self.assertIn('backend="filesystem"', local)
        self.assertIn('and on (cluster,namespace,scanner,pod)', local)
        self.assertIn('@ end() == 1', local)
        self.assertNotIn('or vector(0)', local)
        self.assertIn('kind=~"vulnerability_db|java_db"', panels[38]["targets"][0]["expr"])
        row = next(p for p in all_panels() if p["title"].startswith("Filesystem analysis cache ("))
        self.assertTrue(row["collapsed"])

    def test_pipeline_stages_keep_distinct_populations(self):
        panels = {panel["id"]: panel for panel in all_panels()}
        stages = [panels[i] for i in (63, 20, 22)]
        self.assertEqual(len({p["gridPos"]["y"] for p in stages}), 1)
        self.assertEqual([p["gridPos"]["x"] for p in stages], [0, 8, 16])
        for panel, metric in zip(stages, ("harbor_task_queue_latency", "queue_wait_duration_seconds_bucket", "oldest_running_job_age_seconds")):
            self.assertIn(metric, panel["targets"][0]["expr"])
        self.assertIn("max(", panels[27]["targets"][0]["expr"])
        self.assertIn("queue_unacknowledged_jobs", panels[27]["targets"][0]["expr"])

    def test_current_database_status_has_unknown_and_history(self):
        panels = {panel["id"]: panel for panel in all_panels()}
        for pid in (1032, 1071):
            panel = panels[pid]
            self.assertEqual(panel["type"], "table")
            for target in panel["targets"]:
                self.assertTrue(target["instant"])
                self.assertFalse(target["range"])
                self.assertIn(" == 1", target["expr"])
                self.assertIn(" * 0 - 1", target["expr"])
            overrides = {o["matcher"]["options"]: o["properties"]
                         for o in panel["fieldConfig"]["overrides"]}
            for name in ("Availability", "Update policy"):
                mappings = next(p["value"] for p in overrides[name] if p["id"] == "mappings")
                self.assertEqual(mappings[0]["options"]["-1"]["text"], "Unknown")
        for pid in (85, 88, 94, 95):
            self.assertTrue(panels[pid]["targets"][0]["range"])
            self.assertIn("min by (cluster,namespace,scanner,pod,database)", panels[pid]["targets"][0]["expr"])
        collection = panels[43]
        self.assertIn("storage_last_success_timestamp_seconds", collection["targets"][0]["expr"])
        columns = collection["transformations"][-1]["options"]["renameByName"]
        self.assertEqual(len(columns), 7)  # Replica, then status + last success per collector.
        self.assertEqual(collection["transformations"][0]["options"]["valueLabel"], "collector")
        for collector in ("cache_filesystem", "reports_filesystem", "cache_size"):
            self.assertIn(collector, columns)
            self.assertIn(collector + "-age", columns)

    def test_status_views_have_consistent_dimensions_and_order(self):
        panels = {panel["id"]: panel for panel in all_panels()}
        for pid, width in ((35, 6), (36, 18), (60, 6), (91, 24)):
            self.assertEqual((panels[pid]["gridPos"]["w"], panels[pid]["gridPos"]["h"]), (width, 7))
        self.assertEqual(panels[35]["gridPos"]["x"], 0)
        for ids in ((94, 95), (85, 88)):
            positions = [panels[pid]["gridPos"] for pid in ids]
            self.assertEqual(len({p["y"] for p in positions}), 1)
            self.assertEqual([p["x"] for p in positions], [0, 12])
            self.assertTrue(all((p["w"], p["h"]) == (12, 7) for p in positions))
        self.assertLess(panels[94]["gridPos"]["y"], panels[85]["gridPos"]["y"])
        for pid in (56, 96, 97):
            self.assertEqual(panels[pid]["options"]["textMode"], "auto")


class ValkeyDashboardTest(unittest.TestCase):
    def test_queries_and_selectors_isolate_one_deployment(self):
        variables = {v["name"]: v for v in VALKEY["templating"]["list"]}
        for name in ("cluster", "namespace", "redis_service"):
            self.assertFalse(variables[name]["includeAll"])
            self.assertFalse(variables[name]["multi"])
            self.assertEqual(variables[name]["current"], {})
        for panel in VALKEY["panels"]:
            for target in panel.get("targets", []):
                expr = target["expr"]
                for selector in ('cluster=~"${cluster:regex}"',
                                 'namespace=~"${namespace:regex}"',
                                 'service=~"${redis_service:regex}"', 'service!=""'):
                    self.assertIn(selector, expr)
                self.assertNotIn("or vector(0)", expr)
                self.assertEqual(target["interval"], "1m")

    def test_unknown_idle_and_unlimited_are_distinct(self):
        panels = {p["id"]: p for p in VALKEY["panels"]}
        for pid in (2, 3, 4, 5):
            p = panels[pid]
            self.assertTrue(p["targets"][0]["instant"])
            self.assertIn('"node", "$1", "instance"', p["targets"][0]["expr"])
            self.assertEqual(p["fieldConfig"]["defaults"]["mappings"][0]["options"]["-1"]["text"], "Unknown")
        for pid, text in ((3, "No maxmemory"), (4, "No lookups")):
            self.assertEqual(panels[pid]["fieldConfig"]["defaults"]["mappings"][0]["options"]["-2"]["text"], text)

    def test_layout_and_cross_dashboard_links(self):
        assert_layout(self, VALKEY["panels"])
        for dashboard, destination in ((DASHBOARD, "harbor-valkey"), (VALKEY, "harbor-trivy-scanner")):
            link = next(link for link in dashboard["links"] if '/d/' + destination + '/' in link["url"])
            for variable in ("cluster", "namespace", "redis_service", "scanner"):
                self.assertIn('var-' + variable + '=${' + variable + ':percentencode}', link["url"])


if __name__ == "__main__":
    unittest.main()
