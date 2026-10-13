import argparse
import contextlib
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reconkit import cli, crawl, db, dns_validate, historical, http_map, passive, subdomains, util
from reconkit.scope import Scope


class NetworkGateTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(db.SCHEMA)
        self.scope = Scope(domain="example.com")

    def tearDown(self):
        self.conn.close()

    def test_authorized_flag_takes_no_text_argument(self):
        parser = argparse.ArgumentParser()
        cli._add_scope_args(parser)

        args = parser.parse_args(["--domain", "example.com", "--authorized"])
        scope = cli._build_scope(args)
        self.assertTrue(scope.is_authorized)
        self.assertEqual(scope.authorized_by, "CLI operator assertion")
        self.assertIn("not independently verified", scope.authorization_reference)

        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            parser.parse_args(["--domain", "example.com", "--authorized", "operator name"])

    def test_authorization_flag_omitted_keeps_active_stages_gated(self):
        parser = argparse.ArgumentParser()
        cli._add_scope_args(parser)

        args = parser.parse_args(["--domain", "example.com"])
        scope = cli._build_scope(args)
        self.assertFalse(scope.is_authorized)

    def test_http_map_requires_authorization_before_probing(self):
        with patch("reconkit.http_map._httpx_bulk") as probe:
            result = http_map.run("run-1", "raw", self.scope, self.conn, ["example.com"])

        self.assertEqual(result["status"], "not_run")
        probe.assert_not_called()
        row = self.conn.execute("SELECT status FROM tool_runs").fetchone()
        self.assertEqual(row["status"], "not_run")

    def test_crawl_requires_authorization_before_crawling(self):
        with patch("reconkit.crawl._katana_crawl") as probe:
            result = crawl.run("run-1", "raw", self.scope, self.conn,
                               ["https://example.com/"])

        self.assertEqual(result["status"], "not_run")
        probe.assert_not_called()

    def test_historical_passive_collection_skips_unauthorized_liveness(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            with patch("reconkit.historical._run_tool",
                       return_value=("ok", None, {"https://example.com/"})):
                with patch("reconkit.historical.util.which", return_value="/tools/httpx"):
                    with patch("reconkit.historical.util.run_cmd") as probe:
                        result = historical.run("run-1", raw_dir, self.scope, self.conn)

        self.assertEqual(result["total_historical"], 1)
        self.assertEqual(result["liveness_checked"], 0)
        probe.assert_not_called()
        row = self.conn.execute(
            "SELECT status FROM tool_runs WHERE tool='httpx'"
        ).fetchone()
        self.assertEqual(row["status"], "not_run")
        reachability = self.conn.execute(
            "SELECT currently_reachable FROM historical_urls"
        ).fetchone()
        self.assertIsNone(reachability["currently_reachable"])

    def test_disabled_crawl_module_is_not_invoked(self):
        self.scope.modules["crawl"] = False
        with patch("reconkit.crawl._katana_crawl") as probe:
            result = crawl.run("run-1", "raw", self.scope, self.conn,
                               ["https://example.com/"])

        self.assertEqual(result["status"], "not_run")
        probe.assert_not_called()

    def test_disabled_passive_modules_are_not_invoked(self):
        self.scope.modules["passive"] = False
        self.scope.modules["subdomain_discovery"] = False
        self.scope.modules["dns_validate"] = False
        with patch("reconkit.util.which") as which:
            passive.run("run-1", "raw", self.scope, self.conn)
            subdomains.run("run-1", "raw", self.scope, self.conn)
            dns_validate.run("run-1", "raw", self.scope, self.conn, ["example.com"])

        which.assert_not_called()
        statuses = self.conn.execute(
            "SELECT status FROM tool_runs ORDER BY stage, tool"
        ).fetchall()
        self.assertEqual([row["status"] for row in statuses], ["not_run"] * 4)

    def test_crawler_scope_is_seed_host_only_and_redirects_are_disabled(self):
        authorized_scope = Scope(
            domain="example.com",
            authorized_by="operator",
            authorization_reference="engagement-1",
        )
        seed_urls = ["https://www.example.com/", "https://api.example.com/"]
        with tempfile.TemporaryDirectory() as raw_dir:
            raw_path = str(Path(raw_dir) / "katana.jsonl")
            result = util.CmdResult([], 0, "", "", False, 0.0)
            with patch("reconkit.crawl.util.which", return_value="/tools/katana"):
                with patch("reconkit.crawl.util.run_cmd", return_value=result) as run_cmd:
                    with patch("reconkit.crawl.util.read_jsonl", return_value=[]):
                        crawl._katana_crawl(seed_urls, raw_path, authorized_scope, 10.0)

        command = run_cmd.call_args.args[0]
        self.assertIn("-dr", command)
        scope_regex = command[command.index("-cs") + 1]
        self.assertTrue(scope_regex.startswith("^https?://"))
        self.assertIn("www\\.example\\.com", scope_regex)
        self.assertIn("api\\.example\\.com", scope_regex)
        self.assertNotIn("sso", scope_regex)

    def test_httpx_mapping_does_not_enable_redirect_following(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            raw_path = str(Path(raw_dir) / "httpx.jsonl")
            command_result = util.CmdResult([], 0, "", "", False, 0.0)
            with patch("reconkit.http_map.util.which", return_value="/tools/httpx"):
                with patch("reconkit.http_map.util.run_cmd",
                           return_value=command_result) as run_cmd:
                    with patch("reconkit.http_map.util.read_jsonl", return_value=[]):
                        http_map._httpx_bulk(["example.com"], raw_path, 10.0, 1.0)

        command = run_cmd.call_args.args[0]
        self.assertNotIn("-follow-redirects", command)

    def test_curl_fallback_does_not_follow_redirects(self):
        command_result = util.CmdResult([], 0, "", "", False, 0.0)
        with patch("reconkit.http_map.util.which", return_value="/tools/curl"):
            with patch("reconkit.http_map.util.run_cmd",
                       return_value=command_result) as run_cmd:
                http_map._curl_fallback(["example.com"], "raw", 1.0, 10000.0)

        self.assertGreater(run_cmd.call_count, 0)
        for call in run_cmd.call_args_list:
            self.assertNotIn("-L", call.args[0])

    def test_http_map_records_external_redirect_without_following_it(self):
        authorized_scope = Scope(
            domain="example.com",
            authorized_by="operator",
            authorization_reference="engagement-1",
        )
        rows = [{
            "url": "https://example.com/",
            "status_code": 302,
            "location": "https://outside.example.net/login",
        }]
        with patch("reconkit.http_map._httpx_bulk",
                   return_value={"status": "ok", "rows": rows, "tool": "httpx"}):
            http_map.run("run-1", "raw", authorized_scope, self.conn, ["example.com"])

        observation = self.conn.execute(
            "SELECT points_to, relationship FROM third_party_observations"
        ).fetchone()
        self.assertEqual(observation["points_to"], "outside.example.net")
        self.assertEqual(observation["relationship"], "redirect")


if __name__ == "__main__":
    unittest.main()
