"""OpenStack probe configuration, HTTP health and Prometheus metrics tests."""
import importlib.util
import os
import unittest
from pathlib import Path
from unittest import mock

from prometheus_client import CollectorRegistry, Gauge, Histogram


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/openstack-exporter-app/openstack_exporter.py"
SPEC = importlib.util.spec_from_file_location("openstack_exporter", SCRIPT)
exporter = importlib.util.module_from_spec(SPEC)
# Isolate import-time metrics from other suites and repeated discovery.
REGISTRY = CollectorRegistry()
with mock.patch("prometheus_client.Gauge", side_effect=lambda *a, **kw: Gauge(*a, registry=REGISTRY, **kw)), \
        mock.patch("prometheus_client.Histogram", side_effect=lambda *a, **kw: Histogram(*a, registry=REGISTRY, **kw)):
    SPEC.loader.exec_module(exporter)


class ExporterTests(unittest.TestCase):
    def setUp(self):
        self.session = mock.Mock()
        self.log = mock.patch.object(exporter, "logger")
        self.log.start()
        self.addCleanup(self.log.stop)
        exporter.OPENSTACK_UP.clear()
        exporter.LATENCY.clear()

    def test_load_services_preserves_names_endpoints_and_order(self):
        config = "services:\n  - name: nova\n    endpoint: https://nova.example\n  - name: cinder\n    endpoint: https://cinder.example\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=config)) as opened:
            self.assertEqual(exporter.load_services("targets.yaml"),
                             [("nova", "https://nova.example", "public"), ("cinder", "https://cinder.example", "public")])
        opened.assert_called_once_with("targets.yaml", "r")

    def test_invalid_or_incomplete_config_returns_no_services(self):
        for config in ("", "services: [", "other: []", "services: null", "services: [{name: nova}]", "services: []"):
            with self.subTest(config=config), mock.patch("builtins.open", mock.mock_open(read_data=config)):
                self.assertEqual(exporter.load_services("targets.yaml"), [])

    def test_missing_config_returns_no_services(self):
        with mock.patch("builtins.open", side_effect=FileNotFoundError):
            self.assertEqual(exporter.load_services("missing.yaml"), [])

    def metric(self, name, labels):
        return REGISTRY.get_sample_value(name, labels)

    def test_http_status_sets_health_and_records_latency(self):
        labels = {"service": "nova", "endpoint": "https://nova.example"}
        for status in (199, 200, 204, 299, 300, 401, 503):
            with self.subTest(status=status), \
                    mock.patch.object(exporter.requests, "get", return_value=mock.Mock(status_code=status)) as get, \
                    mock.patch.object(exporter, "time") as clock:
                clock.time.side_effect = [10.0, 10.25]
                exporter.LATENCY.clear()
                exporter.check_service_status("nova", labels["endpoint"], self.session)
                get.assert_called_once_with(labels["endpoint"], headers={"X-Auth-Token": self.session.get_token.return_value},
                                            timeout=5)
                self.assertEqual(self.metric("openstack_api_up", labels), int(200 <= status < 300))
                self.assertEqual(self.metric("openstack_api_latency_seconds_count", {"service": "nova"}), 1)
                self.assertEqual(self.metric("openstack_api_latency_seconds_sum", {"service": "nova"}), 0.25)

    def test_request_failure_marks_previous_healthy_service_down(self):
        labels = {"service": "nova", "endpoint": "https://nova.example"}
        exporter.OPENSTACK_UP.labels(**labels).set(1)
        for error in (exporter.requests.Timeout("timeout"), exporter.requests.ConnectionError("offline")):
            with self.subTest(error=error), mock.patch.object(exporter.requests, "get", side_effect=error):
                exporter.LATENCY.clear()
                exporter.check_service_status("nova", labels["endpoint"], self.session)
                self.assertEqual(self.metric("openstack_api_up", labels), 0)
                self.assertEqual(self.metric("openstack_api_latency_seconds_count", {"service": "nova"}), 1)
                self.assertEqual(self.metric("openstack_api_latency_seconds_sum", {"service": "nova"}), 0)

    def test_token_failure_marks_service_down_without_http_request(self):
        self.session.get_token.side_effect = RuntimeError("authentication failed")
        with mock.patch.object(exporter.requests, "get") as get:
            exporter.check_service_status("nova", "https://nova.example", self.session)
        get.assert_not_called()
        self.assertEqual(self.metric("openstack_api_up", {"service": "nova", "endpoint": "https://nova.example"}), 0)

    def test_main_uses_environment_authentication_and_probes_all_services(self):
        env = {"EXPORTER_PORT": "9101", "AUTH_URL": "https://identity.example/v3", "USERNAME": "user",
               "PASSWORD": "test-secret", "USER_DOMAIN_NAME": "users", "PROJECT_NAME": "project",
               "PROJECT_DOMAIN_NAME": "projects"}
        services = [("nova", "https://nova.example", "public"), ("cinder", "https://cinder.example", "public")]
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(exporter, "start_http_server") as server, \
                mock.patch.object(exporter.v3, "Password") as auth, \
                mock.patch.object(exporter.session, "Session") as session, \
                mock.patch.object(exporter, "load_services", return_value=services) as load, \
                mock.patch.object(exporter, "check_service_status") as check, \
                mock.patch.object(exporter.time, "sleep", side_effect=KeyboardInterrupt) as sleep:
            with self.assertRaises(KeyboardInterrupt):
                exporter.main()
        server.assert_called_once_with(9101)
        auth.assert_called_once_with(auth_url=env["AUTH_URL"], username="user", password="test-secret",
                                     user_domain_name="users", project_name="project", project_domain_name="projects")
        session.assert_called_once_with(auth=auth.return_value)
        load.assert_called_once_with("/etc/openstack-exporter/probe_target.yaml")
        self.assertEqual(check.call_args_list, [mock.call(name, url, session.return_value) for name, url, _ in services])
        sleep.assert_called_once_with(15)

    def test_main_exits_when_no_services_are_loaded(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(exporter, "start_http_server") as server, \
                mock.patch.object(exporter.v3, "Password") as auth, \
                mock.patch.object(exporter.session, "Session"), \
                mock.patch.object(exporter, "load_services", return_value=[]), \
                mock.patch.object(exporter.time, "sleep") as sleep:
            exporter.main()
        server.assert_called_once_with(49152)
        self.assertEqual(auth.call_args.kwargs["user_domain_name"], "Default")
        self.assertEqual(auth.call_args.kwargs["project_name"], "admin")
        self.assertEqual(auth.call_args.kwargs["project_domain_name"], "Default")
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
