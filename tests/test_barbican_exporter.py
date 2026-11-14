"""Barbican exporter tests; Keystone and HTTP calls never leave the process."""
import importlib.util
import os
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/barbican-exporter-app/barbican_exporter.py"
SPEC = importlib.util.spec_from_file_location("barbican_exporter", SCRIPT)
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_auth_url_is_required(self):
        with self.assertRaisesRegex(RuntimeError, "OS_AUTH_URL"):
            exporter._build_keystone_session()

    def test_missing_password_settings_are_reported(self):
        os.environ["OS_AUTH_URL"] = "https://identity.example/v3"
        with self.assertRaisesRegex(RuntimeError, "OS_USERNAME, OS_PASSWORD, OS_PROJECT_NAME"):
            exporter._build_keystone_session()

    def test_application_credentials_take_precedence(self):
        os.environ.update(OS_AUTH_URL="https://identity.example/v3",
                          OS_APPLICATION_CREDENTIAL_ID="app-id",
                          OS_APPLICATION_CREDENTIAL_SECRET="test-secret")
        with mock.patch.object(exporter.ks_v3, "ApplicationCredential") as auth, \
                mock.patch.object(exporter.ks_v3, "Password") as password, \
                mock.patch.object(exporter.ks_session, "Session") as session:
            self.assertIs(exporter._build_keystone_session(), session.return_value)
        auth.assert_called_once_with(auth_url="https://identity.example/v3",
                                     application_credential_id="app-id",
                                     application_credential_secret="test-secret")
        password.assert_not_called()
        session.assert_called_once_with(auth=auth.return_value, verify=True, timeout=10.0)

    def test_password_auth_domains_ca_and_timeout(self):
        for overrides in ({}, {"OS_USER_DOMAIN_NAME": "users", "OS_PROJECT_DOMAIN_NAME": "projects",
                               "OS_CACERT": "/test/ca.pem", "EXPORTER_HTTP_TIMEOUT": "2.5"}):
            with self.subTest(overrides=overrides), mock.patch.dict(os.environ, {
                "OS_AUTH_URL": "https://identity.example/v3", "OS_USERNAME": "user",
                "OS_PASSWORD": "test-secret", "OS_PROJECT_NAME": "project", **overrides
            }, clear=True), mock.patch.object(exporter.ks_v3, "Password") as auth, \
                    mock.patch.object(exporter.ks_session, "Session") as session:
                exporter._build_keystone_session()
                auth.assert_called_once_with(
                    auth_url="https://identity.example/v3", username="user", password="test-secret",
                    project_name="project", user_domain_name=overrides.get("OS_USER_DOMAIN_NAME", "default"),
                    project_domain_name=overrides.get("OS_PROJECT_DOMAIN_NAME", "default"))
                session.assert_called_once_with(auth=auth.return_value,
                                               verify=overrides.get("OS_CACERT", True),
                                               timeout=float(overrides.get("EXPORTER_HTTP_TIMEOUT", "10")))


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.session = mock.Mock()
        self.collector = exporter.BarbicanCollector("https://barbican.example/", self.session,
                                                   cache_ttl_seconds=60, page_limit=2, max_pages=2)
        self.log = mock.patch.object(exporter, "logger")
        self.log.start()
        self.addCleanup(self.log.stop)

    def response(self, data, status=200):
        return mock.Mock(status_code=status, json=mock.Mock(return_value=data), text="error")

    def test_pagination_follows_next_link(self):
        next_url = "https://barbican.example/v1/secrets?offset=2"
        self.session.get.side_effect = [self.response({"secrets": [{}, {}], "next": next_url}),
                                        self.response({"secrets": [{}]})]
        self.assertEqual(self.collector._fetch_count_with_pagination("secrets"), 3)
        self.assertEqual(self.session.get.call_args_list, [
            mock.call("https://barbican.example/v1/secrets?limit=2"), mock.call(next_url)])

    def test_pagination_stops_at_max_pages(self):
        self.session.get.return_value = self.response({"secrets": [{}], "next": "https://next.example"})
        self.assertEqual(self.collector._fetch_count_with_pagination("secrets"), 2)
        self.assertEqual(self.session.get.call_count, 2)

    def test_failed_page_returns_count_so_far(self):
        for failure in (self.response({}, status=503), RuntimeError("offline"),
                        mock.Mock(status_code=200, json=mock.Mock(side_effect=ValueError("invalid JSON")))):
            with self.subTest(failure=failure):
                self.session.get.side_effect = [self.response({"secrets": [{}], "next": "https://next.example"}),
                                                failure]
                self.assertEqual(self.collector._fetch_count_with_pagination("secrets"), 1)

    def test_empty_and_singular_collection_fields(self):
        for payload, expected in (({}, 0), ({"secrets": None}, 0), ({"secret": [{}]}, 1)):
            with self.subTest(payload=payload):
                self.session.get.return_value = self.response(payload)
                self.assertEqual(self.collector._fetch_count_with_pagination("secrets"), expected)

    def test_cache_is_reused_and_refreshed_at_expiry(self):
        with mock.patch.object(self.collector, "_now", return_value=100) as now, \
                mock.patch.object(self.collector, "_fetch_count_with_pagination",
                                  side_effect=[1, 2, 3, 4, 5, 6]) as fetch:
            self.assertEqual(self.collector._get_counts(), {"secrets": 1.0, "containers": 2.0, "orders": 3.0})
            now.return_value = 159
            self.assertEqual(self.collector._get_counts()["secrets"], 1.0)
            self.assertEqual(fetch.call_count, 3)
            now.return_value = 160
            self.assertEqual(self.collector._get_counts(), {"secrets": 4.0, "containers": 5.0, "orders": 6.0})
            self.assertEqual(fetch.call_args_list, [mock.call(name) for name in
                                                   ["secrets", "containers", "orders"] * 2])

    def test_api_health_handles_http_errors_and_connection_failure(self):
        for result, expected in ((self.response({}, 200), 1.0), (self.response({}, 401), 0.0),
                                 (RuntimeError("offline"), 0.0)):
            with self.subTest(expected=expected):
                self.session.get.side_effect = [result]
                self.assertEqual(self.collector._api_up(), expected)
                self.session.get.assert_called_with("https://barbican.example/v1/secrets?limit=1")

    def test_collect_emits_real_prometheus_gauges(self):
        with mock.patch.object(self.collector, "_api_up", return_value=1.0), \
                mock.patch.object(self.collector, "_get_counts", return_value={"secrets": 2.0, "containers": 3.0,
                                                                             "orders": 4.0}):
            metrics = list(self.collector.collect())
        self.assertEqual({metric.name: metric.samples[0].value for metric in metrics},
                         {"barbican_api_up": 1.0, "barbican_secrets_count": 2.0,
                          "barbican_containers_count": 3.0, "barbican_orders_count": 4.0})
        self.assertTrue(all(metric.type == "gauge" for metric in metrics))


if __name__ == "__main__":
    unittest.main()
