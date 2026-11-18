"""Zaqar billing middleware tests; configuration and messaging stay mocked."""
import importlib.util
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from oslo_config import cfg
import oslo_messaging


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts/zaqar-billing-middleware/zaqar-billing-middleware.py"
)
SPEC = importlib.util.spec_from_file_location("billing_middleware", SCRIPT)
billing = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(billing)


class NotifierTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.object(billing, "_notifier", None))
        self.log = self.enterContext(mock.patch.object(billing, "LOG"))
        self.config_factory = self.enterContext(
            mock.patch.object(cfg, "ConfigOpts", autospec=True)
        )
        self.transport_factory = self.enterContext(
            mock.patch.object(oslo_messaging, "get_notification_transport", autospec=True)
        )
        self.notifier_factory = self.enterContext(
            mock.patch.object(oslo_messaging, "Notifier", autospec=True)
        )

    def test_initializes_and_caches_the_billing_notifier(self):
        notifier = billing._get_notifier()

        self.assertIs(notifier, self.notifier_factory.return_value)
        self.assertIs(billing._get_notifier(), notifier)
        self.config_factory.assert_called_once_with()
        self.config_factory.return_value.assert_called_once_with(
            ["--config-file", "/etc/zaqar/zaqar.conf"]
        )
        self.transport_factory.assert_called_once_with(self.config_factory.return_value)
        self.notifier_factory.assert_called_once_with(
            self.transport_factory.return_value,
            publisher_id="zaqar.billing",
            driver="messagingv2",
            topics=["notifications"],
        )

    def test_existing_notifier_does_not_reload_configuration_or_transport(self):
        billing._notifier = mock.sentinel.existing_notifier

        self.assertIs(billing._get_notifier(), mock.sentinel.existing_notifier)

        self.config_factory.assert_not_called()
        self.transport_factory.assert_not_called()
        self.notifier_factory.assert_not_called()

    def test_initialization_failures_return_none_and_can_be_retried(self):
        for stage in (
            self.config_factory.return_value,
            self.transport_factory,
            self.notifier_factory,
        ):
            with self.subTest(stage=stage):
                billing._notifier = None
                self.log.reset_mock()
                failure = RuntimeError("synthetic initialization failure")
                stage.side_effect = failure

                self.assertIsNone(billing._get_notifier())
                self.assertIsNone(billing._notifier)
                self.log.error.assert_called_once_with(
                    "BillingMiddleware: failed to create notifier: %s",
                    failure,
                    exc_info=True,
                )

                stage.side_effect = None
                self.assertIs(billing._get_notifier(), self.notifier_factory.return_value)

    def test_concurrent_first_requests_share_one_notifier(self):
        # Both callers see an empty cache before either can initialize it.
        # The real lock still serializes initialization after the barrier.
        barrier = threading.Barrier(2, timeout=5)
        lock = threading.Lock()

        class ContendedLock:
            def __enter__(self):
                barrier.wait()
                lock.acquire()

            def __exit__(self, *exc_info):
                lock.release()

        with mock.patch.object(billing, "_notifier_lock", ContendedLock()):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(billing._get_notifier) for _ in range(2)]
                results = [future.result(timeout=10) for future in futures]

        for result in results:
            self.assertIs(result, self.notifier_factory.return_value)
        self.config_factory.assert_called_once_with()
        self.transport_factory.assert_called_once_with(self.config_factory.return_value)
        self.notifier_factory.assert_called_once()


class ResourceTypeTests(unittest.TestCase):
    def test_nested_resources_take_precedence_over_the_parent_queue(self):
        for path, expected in (
            ("/v2/queues/orders/messages", "message"),
            ("/v2/queues/orders/messages/message-id", "message"),
            ("/v2/queues/orders/claims", "claim"),
            ("/v2/queues/orders/claims/claim-id", "claim"),
            ("/v2/queues/orders/subscriptions", "subscription"),
            ("/v2/queues/orders/subscriptions/subscription-id", "subscription"),
            ("/v2/queues", "queue"),
            ("/v2/queues/orders", "queue"),
            ("/", "unknown"),
            ("/v2/health", "unknown"),
        ):
            with self.subTest(path=path):
                self.assertEqual(billing._detect_resource_type(path), expected)


class BillingMiddlewareTests(unittest.TestCase):
    def setUp(self):
        self.notifier = mock.Mock(spec=["info"])
        self.get_notifier = self.enterContext(
            mock.patch.object(billing, "_get_notifier", return_value=self.notifier)
        )
        self.log = self.enterContext(mock.patch.object(billing, "LOG"))
        # Patch this module's clock without changing time.time for oslo/logging.
        self.clock = self.enterContext(mock.patch.object(billing, "time"))
        self.status = "200 OK"
        self.headers = [("Content-Type", "application/json"), ("X-Request-ID", "req-1")]
        self.exc_info = None
        self.response = [b'{"ok": true}']
        self.start_response = mock.Mock(return_value=mock.sentinel.write)

        def app(environ, start_response):
            self.writer = start_response(self.status, self.headers, self.exc_info)
            return self.response

        self.app = mock.Mock(side_effect=app)
        self.middleware = billing.BillingMiddleware(self.app)

    def request(self, environ=None):
        self.clock.time.side_effect = [100.0, 100.123456]
        result = self.middleware({} if environ is None else environ, self.start_response)
        self.assertIs(result, self.response)
        return result

    def test_emits_the_expected_payload_and_preserves_the_wsgi_response(self):
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/v2/queues/orders/messages",
            "HTTP_X_PROJECT_ID": "project-1",
            "HTTP_X_TENANT_ID": "other-tenant",
            "HTTP_X_USER_ID": "user-1",
        }
        self.status = "201 Created"
        self.exc_info = (ValueError, ValueError("synthetic recovery"), None)

        self.request(environ)

        self.assertIs(self.app.call_args.args[0], environ)
        self.start_response.assert_called_once_with(self.status, self.headers, self.exc_info)
        self.assertIs(self.start_response.call_args.args[1], self.headers)
        self.assertIs(self.writer, mock.sentinel.write)
        self.get_notifier.assert_called_once_with()
        self.notifier.info.assert_called_once_with(
            {},
            "zaqar.billing.request",
            {
                "project_id": "project-1",
                "user_id": "user-1",
                "method": "POST",
                "path": "/v2/queues/orders/messages",
                "status_code": 201,
                "duration": 0.1235,
                "action": "post",
                "resource_type": "message",
            },
        )

    def test_missing_request_fields_use_the_program_defaults(self):
        self.request()

        self.notifier.info.assert_called_once_with(
            {},
            "zaqar.billing.request",
            {
                "project_id": "",
                "user_id": "",
                "method": "GET",
                "path": "/",
                "status_code": 200,
                "duration": 0.1235,
                "action": "get",
                "resource_type": "unknown",
            },
        )

    def test_tenant_id_is_used_when_project_id_is_missing_or_empty(self):
        for environ in (
            {"HTTP_X_TENANT_ID": "tenant-1"},
            {"HTTP_X_PROJECT_ID": "", "HTTP_X_TENANT_ID": "tenant-1"},
        ):
            with self.subTest(environ=environ):
                self.notifier.info.reset_mock()
                self.request(environ)
                self.notifier.info.assert_called_once()
                self.assertEqual(
                    self.notifier.info.call_args.args[2]["project_id"], "tenant-1"
                )

    def test_http_errors_and_unparseable_statuses_are_still_billed(self):
        for status, expected in (
            ("204 No Content", 204),
            ("404 Not Found", 404),
            ("503 Service Unavailable", 503),
            ("not-an-http-status", 0),
            ("", 0),
        ):
            with self.subTest(status=status):
                self.status = status
                self.notifier.info.reset_mock()
                self.request()
                self.notifier.info.assert_called_once()
                self.assertEqual(
                    self.notifier.info.call_args.args[2]["status_code"], expected
                )

    def test_missing_start_response_status_is_reported_as_zero(self):
        self.app.side_effect = None
        self.app.return_value = self.response

        self.request()

        self.start_response.assert_not_called()
        self.assertEqual(self.notifier.info.call_args.args[2]["status_code"], 0)

    def test_unavailable_notifier_does_not_interrupt_the_response(self):
        self.get_notifier.return_value = None

        self.request()

        self.notifier.info.assert_not_called()
        self.start_response.assert_called_once_with(self.status, self.headers, None)

    def test_notification_failure_is_logged_without_interrupting_the_response(self):
        failure = RuntimeError("synthetic broker failure")
        self.notifier.info.side_effect = failure

        self.request()

        self.log.error.assert_called_once_with(
            "BillingMiddleware: notification error: %s", failure, exc_info=True
        )
        self.start_response.assert_called_once_with(self.status, self.headers, None)

    def test_application_failure_propagates_without_a_billing_notification(self):
        self.app.side_effect = ValueError("synthetic application failure")
        self.clock.time.return_value = 100.0

        with self.assertRaisesRegex(ValueError, "synthetic application failure"):
            self.middleware({}, self.start_response)

        self.get_notifier.assert_not_called()
        self.start_response.assert_not_called()

    def test_response_iterator_is_not_eagerly_consumed(self):
        events = []

        def stream():
            events.append("iterated")
            yield b"streamed response"

        self.response = stream()
        self.addCleanup(self.response.close)

        result = self.request()

        self.assertEqual(events, [])
        self.assertEqual(list(result), [b"streamed response"])
        self.assertEqual(events, ["iterated"])


class FilterFactoryTests(unittest.TestCase):
    def test_paste_factory_wraps_the_supplied_application(self):
        app = mock.Mock()
        factory = billing.filter_factory({"global": "value"}, local="value")

        wrapped = factory(app)

        self.assertIsInstance(wrapped, billing.BillingMiddleware)
        self.assertIs(wrapped.app, app)
        app.assert_not_called()


if __name__ == "__main__":
    unittest.main()
