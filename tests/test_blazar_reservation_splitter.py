"""Reservation transformation and RabbitMQ acknowledgement tests."""
import copy
import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock

from oslo_config import cfg


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/blazar-reservation-splitter-app/blazar-reservation-splitter.py"
SPEC = importlib.util.spec_from_file_location("blazar_reservation_splitter", SCRIPT)
blazar = importlib.util.module_from_spec(SPEC)
# Keep the application's option registration out of the process-wide config.
with mock.patch.object(cfg, "CONF", cfg.ConfigOpts()):
    SPEC.loader.exec_module(blazar)


class SplitterTests(unittest.TestCase):
    def setUp(self):
        self.splitter = blazar.BlazarReservationSplitter()
        self.splitter.channel = mock.Mock()
        self.channel = self.splitter.channel
        self.method = mock.Mock(delivery_tag=42)
        self.payload = {"lease_id": "lease-1", "name": "test lease", "project_id": "project-1",
                        "user_id": "user-1", "trust_id": "trust-1", "start_date": "2026-01-01",
                        "end_date": "2026-01-02", "status": "ACTIVE", "degraded": False,
                        "reservations": []}
        self.log = mock.patch.object(blazar, "logger")
        self.log.start()
        self.addCleanup(self.log.stop)

    def deliver(self, message):
        body = json.dumps(message).encode()
        self.splitter.process_message(self.channel, self.method, None, body)

    def test_missing_or_empty_reservations_produce_no_events(self):
        for payload in ({}, {"reservations": []}):
            with self.subTest(payload=payload):
                self.assertEqual(self.splitter.split_reservations(payload), [])

    def test_split_preserves_context_and_type_specific_fields_without_mutating_input(self):
        variants = {
            "flavor:instance": {"vcpus": 4, "memory_mb": 8192, "disk_gb": 40, "amount": 2,
                                "affinity": False, "resource_properties": "props", "flavor_id": "flavor-1",
                                "aggregate_id": "agg-1", "server_group_id": "group-1"},
            "physical:host": {"hypervisor_properties": "hypervisor", "resource_properties": "props",
                              "before_end": "default", "min": 1, "max": 2},
            "virtual:floatingip": {"amount": 3, "network_id": "net-1"},
        }
        for index, (kind, fields) in enumerate(variants.items()):
            self.payload["reservations"].append({"id": f"reservation-{index}", "resource_id": "resource-1",
                                                 "resource_type": kind, "status": "active",
                                                 "missing_resources": False, "resources_changed": True,
                                                 "created_at": "created", "updated_at": "updated", **fields})
        original = copy.deepcopy(self.payload)
        result = self.splitter.split_reservations(self.payload)
        self.assertEqual(len(result), 3)
        for reservation, output in zip(self.payload["reservations"], result):
            expected = {key: value for key, value in self.payload.items() if key not in ("name", "status", "reservations")}
            expected.update(lease_name="test lease", lease_status="ACTIVE")
            expected.update({key: value for key, value in reservation.items() if key not in ("id", "status")})
            expected.update(reservation_id=reservation["id"], reservation_status="active")
            self.assertEqual(output, expected)
        self.assertEqual(self.payload, original)
        self.assertIsNot(result[0], result[1])

    def test_publish_uses_oslo_envelope_and_persistent_json_messages(self):
        for kind, suffix in (("flavor:instance", "flavor_instance"), ("physical:host", "physical_host"),
                             ("virtual:floatingip", "virtual_floatingip")):
            with self.subTest(kind=kind), mock.patch.object(blazar.time, "time", return_value=123):
                payload = {"reservation_id": "reservation-1", "resource_type": kind}
                self.splitter.publish_reservation_event(payload, "blazar.reservation")
                kwargs = self.channel.basic_publish.call_args.kwargs
                envelope = json.loads(kwargs["body"])
                notification = json.loads(envelope["oslo.message"])
                self.assertEqual(kwargs["exchange"], blazar.CONF.exchange)
                self.assertEqual(kwargs["routing_key"], "notifications.info")
                self.assertEqual(kwargs["properties"].delivery_mode, 2)
                self.assertEqual(kwargs["properties"].content_type, "application/json")
                self.assertEqual(envelope["oslo.version"], "2.0")
                self.assertEqual(notification["event_type"], f"blazar.reservation.{suffix}")
                self.assertEqual(notification["payload"], payload)
                self.assertEqual(notification["message_id"], "reservation-1-123")
                self.assertEqual(notification["publisher_id"], "blazar-reservation-splitter")
                self.assertEqual(notification["priority"], "INFO")

    def test_publish_failure_propagates(self):
        self.channel.basic_publish.side_effect = RuntimeError("broker unavailable")
        with self.assertRaisesRegex(RuntimeError, "broker unavailable"):
            self.splitter.publish_reservation_event({"reservation_id": "r1", "resource_type": "physical:host"},
                                                    "blazar.reservation")

    def test_plain_and_oslo_events_publish_every_reservation_before_ack(self):
        self.payload["reservations"] = [{"id": "r1", "resource_type": "physical:host"},
                                        {"id": "r2", "resource_type": "virtual:floatingip"}]
        notification = {"event_type": "lease.event.start_lease", "payload": self.payload}
        for message in (notification, {"oslo.version": "2.0", "oslo.message": json.dumps(notification)}):
            with self.subTest(message=message):
                self.channel.reset_mock()
                self.deliver(message)
                self.assertEqual([call[0] for call in self.channel.method_calls],
                                 ["basic_publish", "basic_publish", "basic_ack"])
                self.channel.basic_ack.assert_called_once_with(delivery_tag=42)
                self.channel.basic_nack.assert_not_called()
        self.assertEqual(self.splitter.processed_count, 2)
        self.assertEqual(self.splitter.error_count, 0)

    def test_unrelated_and_republished_events_are_acknowledged_without_publish(self):
        for event_type in ("lease.event.end_lease", "blazar.reservation.physical_host", None):
            with self.subTest(event_type=event_type):
                self.channel.reset_mock()
                self.deliver({"event_type": event_type})
                self.channel.basic_ack.assert_called_once_with(delivery_tag=42)
                self.channel.basic_publish.assert_not_called()
                self.channel.basic_nack.assert_not_called()
        self.assertEqual(self.splitter.processed_count, 0)

    def test_empty_target_lease_is_acknowledged(self):
        self.deliver({"event_type": "lease.event.start_lease", "payload": self.payload})
        self.channel.basic_publish.assert_not_called()
        self.channel.basic_ack.assert_called_once_with(delivery_tag=42)
        self.assertEqual(self.splitter.processed_count, 1)

    def test_invalid_outer_and_inner_json_are_rejected_without_requeue(self):
        for body in (b"invalid-json", json.dumps({"oslo.message": "invalid-json"}).encode()):
            with self.subTest(body=body):
                self.channel.reset_mock()
                self.splitter.process_message(self.channel, self.method, None, body)
                self.channel.basic_nack.assert_called_once_with(delivery_tag=42, requeue=False)
                self.channel.basic_ack.assert_not_called()
        self.assertEqual(self.splitter.error_count, 2)
        self.assertEqual(self.splitter.processed_count, 0)

    def test_publish_failure_requeues_without_acknowledging(self):
        self.payload["reservations"] = [{"id": "r1", "resource_type": "physical:host"}]
        self.channel.basic_publish.side_effect = RuntimeError("offline")
        self.deliver({"event_type": "lease.event.start_lease", "payload": self.payload})
        self.channel.basic_nack.assert_called_once_with(delivery_tag=42, requeue=True)
        self.channel.basic_ack.assert_not_called()
        self.assertEqual(self.splitter.error_count, 1)
        self.assertEqual(self.splitter.processed_count, 0)

    def test_stop_closes_open_channel_and_connection(self):
        self.splitter.connection = mock.Mock()
        self.splitter.stop()
        self.channel.stop_consuming.assert_called_once_with()
        self.channel.close.assert_called_once_with()
        self.splitter.connection.close.assert_called_once_with()

    def test_stop_tolerates_missing_or_closed_connections(self):
        self.splitter.channel = None
        self.splitter.stop()
        self.splitter.channel = self.channel
        self.channel.is_open = False
        self.splitter.connection = mock.Mock(is_open=False)
        self.splitter.stop()
        self.channel.close.assert_not_called()
        self.splitter.connection.close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
