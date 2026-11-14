#!/usr/bin/env python3
"""Unit tests for scripts/ipa-log-redactor/ipa-log-redactor.py."""
import argparse
import ast
import importlib.util
import io
import itertools
import json
import os
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "ipa-log-redactor"
    / "ipa-log-redactor.py"
)
SPEC = importlib.util.spec_from_file_location("ipa_log_redactor", SCRIPT_PATH)
ipa_redactor = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(ipa_redactor)


NODE_UUID = "15b5e16a-78dd-4d25-b902-6ae43d4c3d2c"
INSTANCE_UUID = "f685f191-edac-4786-8ee5-b772b0b21d09"


def add_bytes(archive, name, content, member_type=None):
    payload = content.encode("utf-8")
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    if member_type is not None:
        member.type = member_type
    archive.addfile(member, io.BytesIO(payload))


def lifecycle_records(output):
    prefix = ipa_redactor.REDACTOR_TAG + " "
    return [
        json.loads(line[len(prefix):])
        for line in output.splitlines()
        if line.startswith(prefix + "{")
    ]


def structured_records(output):
    prefix = ipa_redactor.REDACTOR_TAG + " "
    return [
        json.loads(line[len(prefix):])
        for line in output.splitlines()
        if line.startswith(prefix + "{")
    ]


def isolated_environment():
    """Keep runtime settings from changing tests that expect script defaults."""
    return {
        name: value
        for name, value in os.environ.items()
        if name != "LOGS_DIR" and name not in ENVIRONMENT_VARIABLES
    }


class StatusEventTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.dict("os.environ", isolated_environment(), clear=True))

    def test_once_mode_emits_startup_inventory_when_directory_is_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = io.StringIO()
            errors = io.StringIO()
            with mock.patch("sys.stdout", output), mock.patch("sys.stderr", errors):
                result = ipa_redactor.main(
                    [
                        "--logs-dir",
                        temp_dir,
                        "--stability-seconds",
                        "0",
                        "--once",
                    ]
                )

        self.assertEqual(result, 0)
        self.assertEqual(errors.getvalue(), "")
        records = structured_records(output.getvalue())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["event"], "redactor_started")
        self.assertEqual(records[0]["status"], "watching")
        self.assertEqual(records[0]["pending_archives"], 0)
        self.assertEqual(records[0]["processing_archives"], 0)
        self.assertEqual(records[0]["forwarded_archives"], 0)
        self.assertEqual(records[0]["failed_archives"], 0)
        self.assertNotIn("scan_interval_seconds", records[0])
        self.assertNotIn("stability_seconds", records[0])
        self.assertNotIn("status_interval_seconds", records[0])

    def test_continuous_mode_emits_periodic_status(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = io.StringIO()
            errors = io.StringIO()
            with (
                mock.patch("sys.stdout", output),
                mock.patch("sys.stderr", errors),
                mock.patch.object(ipa_redactor, "process_available", return_value=0),
                mock.patch.object(
                    ipa_redactor, "cleanup_expired_archives", return_value=0
                ),
                mock.patch.object(
                    ipa_redactor.time, "monotonic", side_effect=[0, 300]
                ),
                mock.patch.object(
                    ipa_redactor.time, "sleep", side_effect=KeyboardInterrupt
                ),
            ):
                result = ipa_redactor.main(
                    [
                        "--logs-dir",
                        temp_dir,
                        "--status-interval-seconds",
                        "300",
                    ]
                )

        self.assertEqual(result, 0)
        self.assertEqual(errors.getvalue(), "")
        records = structured_records(output.getvalue())
        self.assertEqual(
            [record["event"] for record in records],
            ["redactor_started", "redactor_status"],
        )
        self.assertEqual(records[1]["status"], "watching")
        self.assertEqual(records[1]["pending_archives"], 0)


class RedactionTests(unittest.TestCase):
    def test_redacts_every_secret_key_in_supported_formats(self):
        # The independent literal-name assertion below pins SECRET_KEYS, so
        # removing a protected key cannot silently reduce this matrix.
        for key in ipa_redactor.SECRET_KEYS:
            tail = "" if key in ("kernel_append_params", "sshkey", "ssh_authorized_keys") else " tail"
            cases = (
                ("{}=SYNTH", "{}=REDACTED"),
                ("{}: SYNTH", "{}: REDACTED"),
                ("{}=SYNTH tail", "{}=REDACTED" + tail),
                ("{}: SYNTH tail", "{}: REDACTED" + tail),
                ("{} = SYNTH tail", "{}=REDACTED" + tail),
                ("{}='SYNTH' tail", "{}=REDACTED" + tail),
                ('{}="SYNTH secret" tail', "{}=REDACTED" + tail),
                ('{}: "SYNTH secret" tail', "{}: REDACTED" + tail),
                ("x {}=SYNTH", "x {}=REDACTED"),
                ("{{'{}': 'SYNTH secret', 'safe': 'visible'}}",
                 "{{'{}': 'REDACTED', 'safe': 'visible'}}"),
                ('{{"{}": "SYNTH secret", "safe": "visible"}}',
                 '{{"{}": \'REDACTED\', "safe": "visible"}}'),
                ("{{'{}': ['SYNTH']}}", "{{'{}': 'REDACTED'}}"),
                ("{{'{}': {{'a': 'SYNTH'}}}}", "{{'{}': 'REDACTED'}}"),
                ("{{'{}': None}}", "{{'{}': 'REDACTED'}}"),
            )
            for source, expected in cases:
                with self.subTest(key=key, source=source):
                    self.assertEqual(
                        ipa_redactor.redact_line(source.format(key) + "\n"),
                        expected.format(key) + "\n",
                    )
            with self.subTest(key=key.upper(), form="json"):
                source = '{{"{}": "SYNTH secret", "safe": "visible"}}'.format(key.upper())
                expected = '{{"{}": \'REDACTED\', "safe": "visible"}}'.format(key.upper())
                self.assertEqual(ipa_redactor.redact_line(source + "\n"), expected + "\n")

    def test_redacts_assignment_and_dictionary_formats(self):
        source = (
            'rootpwd="root-secret" sshkey="ssh-rsa key-material user@host"\n'
            "{'agent_token': 'token-secret', 'image_server_password': 'image-secret'}\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertNotIn("root-secret", result)
        self.assertNotIn("key-material", result)
        self.assertNotIn("token-secret", result)
        self.assertNotIn("image-secret", result)
        self.assertIn("rootpwd=REDACTED", result)
        self.assertIn("sshkey=REDACTED", result)

    def test_redacts_entire_kernel_append_params_value(self):
        source = "kernel_append_params = console=ttyS0 rootpwd=secret sshkey=secret\n"
        self.assertEqual(
            ipa_redactor.redact_line(source), "kernel_append_params=REDACTED\n"
        )

    def test_known_keys_are_case_insensitive(self):
        source = (
            "ROOTPWD=synthetic-root-secret\n"
            "SSHKEY=ssh-rsa SyntheticKeyMaterial fake@example.invalid\n"
            "{'IMAGE_SERVER_PASSWORD': 'synthetic-image-secret'}\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertNotIn("synthetic-root-secret", result)
        self.assertNotIn("SyntheticKeyMaterial", result)
        self.assertNotIn("synthetic-image-secret", result)
        self.assertIn("ROOTPWD=REDACTED", result)
        self.assertIn("SSHKEY=REDACTED", result)
        self.assertIn("'IMAGE_SERVER_PASSWORD': 'REDACTED'", result)

    def test_colon_form_redacts_unquoted_token_and_keeps_surrounding_text(self):
        result = ipa_redactor.redact_line("sent ipa-agent-token: synthetic-token ok\n")
        self.assertEqual(result, "sent ipa-agent-token: REDACTED ok\n")

    def test_colon_form_tail_keys_redact_through_end_of_line(self):
        result = ipa_redactor.redact_line(
            "ssh_authorized_keys: ssh-rsa SyntheticKeyMaterial user@example.invalid\n"
        )
        self.assertEqual(result, "ssh_authorized_keys: REDACTED\n")

    def test_colon_form_does_not_double_redact_dictionary_form(self):
        result = ipa_redactor.redact_line("{'agent_token': 'synthetic-token'}\n")
        self.assertEqual(result, "{'agent_token': 'REDACTED'}\n")

    def test_redacts_auth_headers_in_every_form(self):
        for header in ipa_redactor.AUTH_HEADER_KEYS:
            cases = (
                (header + ": Bearer SYNTH", header + ": REDACTED"),
                ("headers={{'{}': 'Bearer SYNTH', 'Accept': 'json'}}".format(header),
                 "headers={{'{}': 'REDACTED', 'Accept': 'json'}}".format(header)),
                ('{{"{}": "SYNTH", "Accept": "json"}}'.format(header),
                 '{{"{}": \'REDACTED\', "Accept": "json"}}'.format(header)),
                (header + "=SYNTH next=value", header + "=REDACTED next=value"),
                (header.lower() + "=SYNTH next=value", header.lower() + "=REDACTED next=value"),
                ("{{'{}': 'SYNTH', 'k': 1}}".format(header),
                 "{{'{}': 'REDACTED', 'k': 1}}".format(header)),
            )
            for source, expected in cases:
                with self.subTest(header=header, source=source):
                    self.assertEqual(ipa_redactor.redact_line(source + "\n"), expected + "\n")

    def test_auth_header_assignment_keeps_scheme_and_token_together(self):
        for header in ipa_redactor.AUTH_HEADER_KEYS:
            for scheme in ("", "Bearer", "Basic", "Digest", "Negotiate", "bEaReR"):
                value = "{} SYNTH".format(scheme) if scheme else "SYNTH"
                for quote in ("", "'", '"'):
                    source = "{}={}{}{} next=value\n".format(header, quote, value, quote)
                    with self.subTest(header=header, scheme=scheme, quote=quote):
                        self.assertEqual(
                            ipa_redactor.redact_line(source),
                            "{}=REDACTED next=value\n".format(header),
                        )

    def test_auth_header_names_are_case_insensitive(self):
        for source in (
            "authorization: synthetic-secret\n",
            "X-AUTH-TOKEN: synthetic-secret\n",
            "{'x-subject-token': 'synthetic-secret'}\n",
        ):
            with self.subTest(source=source):
                self.assertNotIn(
                    "synthetic-secret", ipa_redactor.redact_line(source)
                )

    def test_unrelated_headers_are_not_redacted(self):
        source = "Content-Type: application/json\nAccept: text/plain\n"
        self.assertEqual(ipa_redactor.redact_line(source), source)

    def test_redacts_credentials_for_any_url_scheme(self):
        for scheme in ("http", "https", "HTTP", "ftp", "ftps", "sftp"):
            with self.subTest(scheme=scheme):
                source = "use {}://fake-user:fake-password@example.invalid/path\n".format(
                    scheme
                )
                result = ipa_redactor.redact_line(source)
                self.assertEqual(
                    result, "use {}://REDACTED@example.invalid/path\n".format(scheme)
                )
                self.assertNotIn("fake-password", result)

    def test_url_password_containing_at_sign_is_fully_redacted(self):
        result = ipa_redactor.redact_line("https://fake-user:fake@pass@example.invalid/x\n")
        self.assertEqual(result, "https://REDACTED@example.invalid/x\n")

    def test_urls_without_credentials_are_unchanged(self):
        for source in (
            "ftp://example.invalid/pub/file.img\n",
            "https://example.invalid:8080/path@name\n",
            "ssh://git@example.invalid:22/repo\n",
        ):
            with self.subTest(source=source):
                self.assertEqual(ipa_redactor.redact_line(source), source)

    def test_redacts_pgp_private_key_block(self):
        lines = (
            "before\n",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n",
            "synthetic-pgp-key-content\n",
            "-----END PGP PRIVATE KEY BLOCK-----\n",
            "after\n",
        )
        redactor = ipa_redactor.Redactor()
        result = "".join(
            redacted
            for redacted in (redactor.redact(line) for line in lines)
            if redacted is not None
        )
        self.assertEqual(result, "before\n[REDACTED PRIVATE KEY]\nafter\n")
        self.assertNotIn("synthetic-pgp-key-content", result)

    def test_redacts_single_line_pgp_private_key_block(self):
        redactor = ipa_redactor.Redactor()
        result = redactor.redact(
            "-----BEGIN PGP PRIVATE KEY BLOCK----- synthetic -----END PGP PRIVATE KEY BLOCK-----\n"
        )
        self.assertEqual(result, "[REDACTED PRIVATE KEY]\n")
        self.assertFalse(redactor.in_private_key)

    # The following tests use synthetic values in the exact line shapes seen in
    # captured IPA provisioning and cleaning logs. No real values are included.

    def test_redacts_agent_token_in_ipa_request_url_query(self):
        source = (
            "Sep 10 02:24:24 ubuntu ironic-python-agent[3620]: 2026-09-10 02:24:24.087 "
            "3620 INFO ironic_python_agent.api [-] ::ffff:192.0.2.10 - "
            "GET /v1/commands/?agent_token=SYNTH-query-token-0123456789_abcdef - 200 (0.37ms)\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertNotIn("SYNTH-query-token", result)
        self.assertIn("GET /v1/commands/?agent_token=REDACTED - 200 (0.37ms)", result)

    def test_redacts_agent_token_in_oslo_config_option_dump(self):
        source = (
            "2026-09-10 02:24:20.737 3620 DEBUG ironic_python_agent.cmd.agent [-] "
            "agent_token                    = SYNTH-option-token-0123456789 "
            "log_opt_values /opt/ironic-python-agent/lib/python3.12/site-packages/"
            "oslo_config/cfg.py:2995\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertNotIn("SYNTH-option-token", result)
        self.assertIn("agent_token=REDACTED log_opt_values /opt/", result)

    def test_redacts_rootpwd_in_kernel_command_line_and_keeps_other_parameters(self):
        source = (
            "Sep 10 02:21:46 ubuntu kernel: Command line: deploy_kernel selinux=0 "
            "troubleshoot=0 text nofb nomodeset vga=normal ipa-debug=1 "
            "ipa-api-url=https://ironic.example.invalid "
            "rootpwd=SYNTH/root+pwd=value-0123456789 "
            "ipa-global-request-id=req-SYNTH BOOTIF=00:00:5e:00:53:01 "
            "initrd=deploy_ramdisk\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertNotIn("SYNTH/root", result)
        self.assertNotIn("value-0123456789", result)
        self.assertIn("rootpwd=REDACTED ipa-global-request-id=req-SYNTH", result)
        self.assertIn("ipa-api-url=https://ironic.example.invalid", result)
        self.assertIn("BOOTIF=00:00:5e:00:53:01 initrd=deploy_ramdisk", result)

    def test_redacts_redfish_credentials_in_driver_info_and_keeps_address(self):
        source = (
            "Executing command: deploy.get_deploy_steps with args: {'node': {'id': 31, "
            "'driver': 'redfish', 'driver_info': {'redfish_username': 'synth-bmc-user', "
            "'redfish_password': 'SYNTH-bmc-pass', "
            "'redfish_address': 'https://192.0.2.20', 'redfish_verify_ca': 'False', "
            "'kernel_append_params': 'nomodeset rootpwd=SYNTH-nested sshkey=SYNTH-key'}}}\n"
        )
        result = ipa_redactor.redact_line(source)
        for secret in ("synth-bmc-user", "SYNTH-bmc-pass", "SYNTH-nested", "SYNTH-key"):
            self.assertNotIn(secret, result)
        self.assertIn("'redfish_username': 'REDACTED'", result)
        self.assertIn("'redfish_password': 'REDACTED'", result)
        self.assertIn("'redfish_address': 'https://192.0.2.20'", result)
        self.assertIn("'redfish_verify_ca': 'False'", result)

    def test_redacts_agent_token_and_configdrive_in_lookup_results(self):
        configdrive = "SYNTH" + ("A1b2/C3d4+" * 200)
        source = (
            "Received lookup results: {'node': {'uuid': 'synthetic', "
            "'properties': {'cpus': 32, 'vendor': 'Example Inc.'}, "
            "'instance_info': {'image_type': 'whole-disk', "
            "'configdrive': '" + configdrive + "', 'image_url': '******', "
            "'image_checksum': None}}, 'config': {'agent_token': 'SYNTH-lookup-token', "
            "'agent_token_required': True}}\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertNotIn("SYNTH", result)
        self.assertNotIn("A1b2/C3d4+", result)
        self.assertIn("'configdrive': 'REDACTED'", result)
        self.assertIn("'agent_token': 'REDACTED'", result)
        self.assertIn("'agent_token_required': True", result)
        self.assertIn("'vendor': 'Example Inc.'", result)

    def test_already_masked_values_stay_masked(self):
        source = (
            "{'agent_secret_token': '******', 'redfish_password': '******', "
            "'image_server_password': None}\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertNotIn("******", result)
        self.assertIn("'agent_secret_token': 'REDACTED'", result)
        self.assertIn("'redfish_password': 'REDACTED'", result)

    def test_benign_kernel_and_systemd_lines_are_unchanged(self):
        for source in (
            "MPTCP token hash table entries: 65536 (order: 9, 1572864 bytes, linear)\n",
            "systemd[1]: Started systemd-ask-password-wall.path - Forward Password Requests to Wall Directory Watch.\n",
            "systemd[1]: Starting ssh-keygen.service - OpenSSH Server Key Generation...\n",
            "integrity: Platform Keyring initialized\n",
            "systemd[1]: Reached target basic.target - Basic System.\n",
        ):
            with self.subTest(source=source):
                self.assertEqual(ipa_redactor.redact_line(source), source)

    def test_redacts_swift_temp_url_signature_and_keeps_expiry(self):
        source = (
            "downloading http://swift.example.invalid:8080/v1/AUTH_synthetic/images/os.img"
            "?temp_url_sig=SYNTH0123456789abcdef&temp_url_expires=1893456000 now\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertEqual(
            result,
            "downloading http://swift.example.invalid:8080/v1/AUTH_synthetic/images/os.img"
            "?temp_url_sig=REDACTED&temp_url_expires=1893456000 now\n",
        )

    def test_redacts_swift_temp_url_when_signature_is_not_first_parameter(self):
        source = (
            "http://swift.example.invalid/v1/AUTH_synthetic/c/o"
            "?temp_url_expires=1893456000&temp_url_sig=SYNTH0123456789abcdef"
            "&filename=os.img\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertNotIn("SYNTH0123456789abcdef", result)
        self.assertIn("temp_url_expires=1893456000", result)
        self.assertIn("temp_url_sig=REDACTED&filename=os.img", result)

    def test_redacts_s3_presigned_url_credential_and_signature(self):
        source = (
            "https://images.s3.example.invalid/os.img"
            "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
            "&X-Amz-Credential=SYNTHAKID%2F20260101%2Fus-east-1%2Fs3%2Faws4_request"
            "&X-Amz-Date=20260101T000000Z&X-Amz-Expires=3600"
            "&X-Amz-Security-Token=SYNTH%2Bsession%2Ftoken%3D"
            "&X-Amz-SignedHeaders=host&X-Amz-Signature=SYNTH0123456789abcdef\n"
        )
        result = ipa_redactor.redact_line(source)
        for secret in ("SYNTHAKID", "SYNTH%2Bsession", "SYNTH0123456789abcdef"):
            self.assertNotIn(secret, result)
        self.assertIn("X-Amz-Credential=REDACTED", result)
        self.assertIn("X-Amz-Security-Token=REDACTED", result)
        self.assertIn("X-Amz-Signature=REDACTED", result)
        self.assertIn("X-Amz-Algorithm=AWS4-HMAC-SHA256", result)
        self.assertIn("X-Amz-Date=20260101T000000Z", result)
        self.assertIn("X-Amz-Expires=3600", result)
        self.assertIn("X-Amz-SignedHeaders=host", result)

    def test_redacts_legacy_s3_query_authentication(self):
        source = (
            "http://images.s3.example.invalid/os.img?AWSAccessKeyId=SYNTHAKID"
            "&Expires=1893456000&Signature=SYNTH%2Bsig%3D\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertEqual(
            result,
            "http://images.s3.example.invalid/os.img?AWSAccessKeyId=REDACTED"
            "&Expires=1893456000&Signature=REDACTED\n",
        )

    def test_redacts_generic_token_and_sig_query_parameters(self):
        source = "GET http://files.example.invalid/os.img?token=SYNTH-tok&sig=SYNTH-sig&v=2\n"
        result = ipa_redactor.redact_line(source)
        self.assertEqual(
            result,
            "GET http://files.example.invalid/os.img?token=REDACTED&sig=REDACTED&v=2\n",
        )

    def test_query_parameter_names_are_case_insensitive(self):
        for source in (
            "http://x.example.invalid/o?TEMP_URL_SIG=SYNTH-secret\n",
            "http://x.example.invalid/o?x-amz-signature=SYNTH-secret\n",
            "http://x.example.invalid/o?a=1&SIGNATURE=SYNTH-secret\n",
        ):
            with self.subTest(source=source):
                self.assertNotIn("SYNTH-secret", ipa_redactor.redact_line(source))

    def test_redacts_signed_image_url_inside_ipa_dictionary(self):
        source = (
            "{'instance_info': {'image_type': 'whole-disk', 'image_url': "
            "'http://swift.example.invalid/v1/AUTH_synthetic/c/o"
            "?temp_url_sig=SYNTH0123456789abcdef&temp_url_expires=1893456000', "
            "'image_checksum': None}}\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertNotIn("SYNTH0123456789abcdef", result)
        self.assertIn("temp_url_sig=REDACTED&temp_url_expires=1893456000'", result)
        self.assertIn("'image_checksum': None}}", result)

    def test_signed_url_redaction_stops_at_surrounding_punctuation(self):
        for source, expected in (
            (
                "(http://x.example.invalid/o?sig=SYNTH-secret) done\n",
                "(http://x.example.invalid/o?sig=REDACTED) done\n",
            ),
            (
                "urls: [http://x.example.invalid/o?token=SYNTH-secret], next\n",
                "urls: [http://x.example.invalid/o?token=REDACTED], next\n",
            ),
            (
                "href=\"http://x.example.invalid/o?a=1&amp;sig=SYNTH-secret\" rel=x\n",
                "href=\"http://x.example.invalid/o?a=1&amp;sig=REDACTED\" rel=x\n",
            ),
            (
                "fetch http://x.example.invalid/o?sig=SYNTH-secret#fragment\n",
                "fetch http://x.example.invalid/o?sig=REDACTED#fragment\n",
            ),
        ):
            with self.subTest(source=source):
                self.assertEqual(ipa_redactor.redact_line(source), expected)

    def test_urls_without_signature_parameters_are_unchanged(self):
        for source in (
            "http://10.0.0.1:8080/agent_images/00000000-0000-0000-0000-000000000000\n",
            "http://x.example.invalid/sig/token/file.img?name=sig&kind=token\n",
            "http://x.example.invalid/o?mytoken=value&design=1&assignment=2\n",
            "http://x.example.invalid/o?temp_url_expires=1893456000&filename=a.img\n",
            "https://www.isc.org/software/dhcp/\n",
        ):
            with self.subTest(source=source):
                self.assertEqual(ipa_redactor.redact_line(source), source)

    # Prefixed key names.

    def test_redacts_prefixed_keys_in_assignment_form(self):
        for key in ipa_redactor.SECRET_KEYS:
            for prefix in ("synth_", "synth.", "synth-"):
                with self.subTest(key=key, prefix=prefix):
                    result = ipa_redactor.redact_line(
                        "{}{}=SYNTH-secret next=value\n".format(prefix, key)
                    )
                    self.assertNotIn("SYNTH-secret", result)
                    self.assertIn("{}{}=REDACTED".format(prefix, key), result)

    def test_redacts_prefixed_keys_in_colon_and_dictionary_forms(self):
        for source in (
            "synth_agent_token: SYNTH-secret next=value\n",
            "{'synth_redfish_password': 'SYNTH-secret', 'safe': 'visible'}\n",
            '{"my-rootpwd": "SYNTH-secret", "safe": "visible"}\n',
            "{'x_Authorization': 'Bearer SYNTH-secret', 'safe': 'visible'}\n",
        ):
            with self.subTest(source=source):
                result = ipa_redactor.redact_line(source)
                self.assertNotIn("SYNTH-secret", result)

    def test_keys_that_only_start_with_a_secret_name_are_not_redacted(self):
        for source in (
            "agent_token_required=True next=value\n",
            "{'agent_token_required': True, 'agent_url': 'http://192.0.2.1:9999'}\n",
            "configdrive_enabled=true\n",
            "rootpwd_file=/etc/rootpwd.hash\n",
        ):
            with self.subTest(source=source):
                self.assertEqual(ipa_redactor.redact_line(source), source)

    # Quoted values in assignment form.

    def test_escaped_quotes_do_not_end_a_quoted_assignment_value(self):
        for source, expected in (
            (
                "redfish_password='ab\\'SYNTH-tail' next=value\n",
                "redfish_password=REDACTED next=value\n",
            ),
            (
                'rootpwd="ab\\"SYNTH-tail" next=value\n',
                "rootpwd=REDACTED next=value\n",
            ),
            (
                "agent_token='back\\\\slash' next=value\n",
                "agent_token=REDACTED next=value\n",
            ),
        ):
            with self.subTest(source=source):
                result = ipa_redactor.redact_line(source)
                self.assertEqual(result, expected)
                self.assertNotIn("SYNTH-tail", result)

    def test_unterminated_quote_redacts_the_rest_of_the_line(self):
        for source, expected in (
            ('agent_token="SYNTH-secret\n', "agent_token=REDACTED\n"),
            (
                "agent_token='SYNTH-secret more words and=pairs\n",
                "agent_token=REDACTED\n",
            ),
            (
                "before rootpwd=\"SYNTH-secret more\r\n",
                "before rootpwd=REDACTED\r\n",
            ),
        ):
            with self.subTest(source=source):
                result = ipa_redactor.redact_line(source)
                self.assertEqual(result, expected)
                self.assertNotIn("SYNTH-secret", result)

    def test_terminated_quotes_still_preserve_text_after_the_value(self):
        source = "agent_token = \"two words\" tail='kept' rootpwd='a b' more\n"
        self.assertEqual(
            ipa_redactor.redact_line(source),
            "agent_token=REDACTED tail='kept' rootpwd=REDACTED more\n",
        )

    def test_unterminated_quote_in_dictionary_form_redacts_the_rest_of_the_line(self):
        result = ipa_redactor.redact_line("{'agent_token': 'SYNTH-secret more words\n")
        self.assertEqual(result, "{'agent_token': 'REDACTED'\n")
        self.assertNotIn("SYNTH-secret", result)

    # Nested dictionary and list values.

    def test_redacts_nested_configdrive_dictionary_and_keeps_following_keys(self):
        source = (
            "{'instance_info': {'configdrive': {'meta_data': {'hostname': 'synth'}, "
            "'user_data': '#cloud-config\\nchpasswd: SYNTH-secret', "
            "'network_data': {'links': [{'id': 'eth0'}]}}, "
            "'image_type': 'whole-disk'}, 'agent_token_required': True}\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertNotIn("SYNTH-secret", result)
        self.assertNotIn("hostname", result)
        self.assertNotIn("eth0", result)
        self.assertEqual(
            result,
            "{'instance_info': {'configdrive': 'REDACTED', "
            "'image_type': 'whole-disk'}, 'agent_token_required': True}\n",
        )

    def test_nested_value_with_brackets_inside_strings_is_balanced_correctly(self):
        source = (
            "{'configdrive': {'user_data': 'closing } and ] inside SYNTH-secret', "
            "'other': \"quote ' and { inside\"}, 'safe': 'visible'}\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertEqual(result, "{'configdrive': 'REDACTED', 'safe': 'visible'}\n")

    def test_secret_keys_inside_a_redacted_value_do_not_break_the_line(self):
        source = (
            "{'configdrive': {'agent_token': 'SYNTH-inner', 'x': 1}, "
            "'agent_token': 'SYNTH-outer', 'safe': 'visible'}\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertEqual(
            result,
            "{'configdrive': 'REDACTED', 'agent_token': 'REDACTED', 'safe': 'visible'}\n",
        )

    def test_unbalanced_nested_value_redacts_the_rest_of_the_line(self):
        result = ipa_redactor.redact_line(
            "{'configdrive': {'user_data': 'SYNTH-secret', 'more': {'a': 1}\n"
        )
        self.assertEqual(result, "{'configdrive': 'REDACTED'\n")

    def test_list_values_and_scalars_are_still_redacted(self):
        source = (
            "{'ssh_authorized_keys': ['SYNTH-key-1', ['SYNTH-key-2']], "
            "'agent_token': None, 'rootpwd': 12345, 'safe': 'visible'}\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertEqual(
            result,
            "{'ssh_authorized_keys': 'REDACTED', 'agent_token': 'REDACTED', "
            "'rootpwd': 'REDACTED', 'safe': 'visible'}\n",
        )

    def test_dictionary_redaction_preserves_line_endings(self):
        for ending in ("", "\n", "\r\n"):
            with self.subTest(ending=repr(ending)):
                result = ipa_redactor.redact_line("{'configdrive': {'a': 'SYNTH'}}" + ending)
                self.assertEqual(result, "{'configdrive': 'REDACTED'}" + ending)

    def test_redacts_bare_ssh_public_key_material_and_comment(self):
        source = (
            "key ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQFakeMaterial "
            "fake@example.invalid\n"
        )
        result = ipa_redactor.redact_line(source)
        self.assertEqual(result, "key SSH_PUBLIC_KEY_REDACTED\n")
        self.assertNotIn("FakeMaterial", result)

    def test_redacts_multiline_private_key_block(self):
        lines = (
            "before\n",
            "-----BEGIN PRIVATE KEY-----\n",
            "synthetic-private-key-content\n",
            "-----END PRIVATE KEY-----\n",
            "after\n",
        )
        redactor = ipa_redactor.Redactor()
        result = "".join(
            redacted
            for redacted in (redactor.redact(line) for line in lines)
            if redacted is not None
        )
        self.assertEqual(result, "before\n[REDACTED PRIVATE KEY]\nafter\n")
        self.assertNotIn("synthetic-private-key-content", result)


class ArgumentTests(unittest.TestCase):
    def test_logs_dir_can_come_from_environment(self):
        with mock.patch.dict("os.environ", {"LOGS_DIR": "/runtime/ipa-logs"}, clear=True):
            args = ipa_redactor.build_parser().parse_args([])
        self.assertEqual(args.logs_dir, Path("/runtime/ipa-logs"))
        self.assertEqual(args.interval, 30.0)
        self.assertEqual(args.max_archive_members, 1024)
        self.assertEqual(args.forwarded_retention_days, 90)
        self.assertEqual(args.failed_retention_days, 90)
        self.assertEqual(args.cleanup_interval_seconds, 3600)
        self.assertEqual(args.status_interval_seconds, 300)
        self.assertEqual(args.stability_seconds, 60)
        self.assertEqual(args.max_archive_bytes, 32 * 1024 * 1024)
        self.assertEqual(args.max_total_archive_bytes, 512 * 1024 * 1024)
        self.assertEqual(args.max_member_bytes, 64 * 1024 * 1024)
        self.assertEqual(args.max_line_bytes, 1024 * 1024)
        self.assertEqual(args.max_total_output_bytes, 256 * 1024 * 1024)
        self.assertEqual(args.max_output_lines, 100_000)
        self.assertEqual(args.max_forwarded_bytes, 256 * 1024 * 1024)
        self.assertTrue(args.retention_dry_run)

    def test_logs_dir_can_come_from_command_line(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            args = ipa_redactor.build_parser().parse_args(["--logs-dir", "/mounted/logs"])
        self.assertEqual(args.logs_dir, Path("/mounted/logs"))

    def test_logs_dir_is_required_when_environment_is_unset(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            parser = ipa_redactor.build_parser()
            with mock.patch("sys.stderr", io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args([])

    def test_blank_logs_dir_environment_is_treated_as_unset(self):
        for value in ("", "   ", "\t"):
            with self.subTest(value=value):
                with mock.patch.dict("os.environ", {"LOGS_DIR": value}, clear=True):
                    parser = ipa_redactor.build_parser()
                    errors = io.StringIO()
                    with mock.patch("sys.stderr", errors):
                        with self.assertRaises(SystemExit) as raised:
                            parser.parse_args([])
                self.assertEqual(raised.exception.code, 2)
                # Same message as a variable that was never set.
                self.assertIn("the following arguments are required", errors.getvalue())

    def test_blank_logs_dir_environment_can_be_overridden_on_command_line(self):
        with mock.patch.dict("os.environ", {"LOGS_DIR": ""}, clear=True):
            args = ipa_redactor.build_parser().parse_args(["--logs-dir", "/mounted/logs"])
        self.assertEqual(args.logs_dir, Path("/mounted/logs"))

    def test_blank_logs_dir_command_line_value_is_rejected(self):
        for value in ("", "  "):
            with self.subTest(value=value):
                with mock.patch.dict("os.environ", {"LOGS_DIR": "/runtime/logs"}, clear=True):
                    parser = ipa_redactor.build_parser()
                    errors = io.StringIO()
                    with mock.patch("sys.stderr", errors):
                        with self.assertRaises(SystemExit) as raised:
                            parser.parse_args(["--logs-dir", value])
                self.assertEqual(raised.exception.code, 2)
                self.assertIn("must not be empty", errors.getvalue())

    def test_retry_settings_have_defaults_and_can_be_overridden(self):
        with mock.patch.dict("os.environ", {"LOGS_DIR": "/logs"}, clear=True):
            args = ipa_redactor.build_parser().parse_args([])
        self.assertEqual(args.max_processing_attempts, 3)
        self.assertEqual(args.retry_backoff_seconds, 60.0)

        environment = {
            "LOGS_DIR": "/logs",
            "MAX_PROCESSING_ATTEMPTS": "5",
            "RETRY_BACKOFF_SECONDS": "15",
        }
        with mock.patch.dict("os.environ", environment, clear=True):
            args = ipa_redactor.build_parser().parse_args([])
        self.assertEqual(args.max_processing_attempts, 5)
        self.assertEqual(args.retry_backoff_seconds, 15.0)

    def test_retention_can_be_overridden_or_disabled_by_environment(self):
        environment = {
            "LOGS_DIR": "/runtime/ipa-logs",
            "FORWARDED_RETENTION_DAYS": "180",
            "FAILED_RETENTION_DAYS": "0",
            "CLEANUP_INTERVAL_SECONDS": "7200",
            "STATUS_INTERVAL_SECONDS": "600",
            "STABILITY_SECONDS": "120",
            "MAX_ARCHIVE_BYTES": "1048576",
            "MAX_TOTAL_ARCHIVE_BYTES": "4194304",
            "MAX_MEMBER_BYTES": "2097152",
            "MAX_LINE_BYTES": "1048576",
            "MAX_TOTAL_OUTPUT_BYTES": "268435456",
            "MAX_OUTPUT_LINES": "200000",
            "MAX_FORWARDED_BYTES": "134217728",
            "RETENTION_DRY_RUN": "false",
        }
        with mock.patch.dict("os.environ", environment, clear=True):
            args = ipa_redactor.build_parser().parse_args([])
        self.assertEqual(args.forwarded_retention_days, 180)
        self.assertEqual(args.failed_retention_days, 0)
        self.assertEqual(args.cleanup_interval_seconds, 7200)
        self.assertEqual(args.status_interval_seconds, 600)
        self.assertEqual(args.stability_seconds, 120)
        self.assertEqual(args.max_archive_bytes, 1048576)
        self.assertEqual(args.max_total_archive_bytes, 4194304)
        self.assertEqual(args.max_member_bytes, 2097152)
        self.assertEqual(args.max_line_bytes, 1048576)
        self.assertEqual(args.max_total_output_bytes, 268435456)
        self.assertEqual(args.max_output_lines, 200000)
        self.assertEqual(args.max_forwarded_bytes, 134217728)
        self.assertFalse(args.retention_dry_run)


class BundleNameTests(unittest.TestCase):
    def bundle_path(self, node_name, context="cleaning"):
        return Path(
            "{}_{}_{}_2026-09-25-12-00-00.tar.gz.processing".format(
                NODE_UUID, node_name, context
            )
        )

    def test_accepts_safe_node_name_variants(self):
        for node_name in (
            "node2",
            "node3",
            "compute.example.com",
            "1362744_ceph2",
        ):
            with self.subTest(node_name=node_name):
                self.assertEqual(
                    ipa_redactor.parse_bundle_name(self.bundle_path(node_name)),
                    (node_name, "cleaning"),
                )

    def test_node_name_with_underscore_parses_before_instance_uuid(self):
        node_name = "1362744_ceph2"
        self.assertEqual(
            ipa_redactor.parse_bundle_name(self.bundle_path(node_name, INSTANCE_UUID)),
            (node_name, INSTANCE_UUID),
        )

    def test_rejects_node_names_with_whitespace_or_control_characters(self):
        for node_name in ("compute 3", "compute\t3", "compute\n3", "compute\x1b3"):
            with self.subTest(node_name=repr(node_name)):
                with self.assertRaises(ipa_redactor.BundleError):
                    ipa_redactor.parse_bundle_name(self.bundle_path(node_name))


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.logs_dir = Path(self.temp_dir.name)
        self.output = io.StringIO()
        self.errors = io.StringIO()
        self.now = 2_000_000_000.0

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_file(self, name, age_days):
        path = self.logs_dir / name
        path.write_bytes(b"archive")
        modified = self.now - (age_days * ipa_redactor.SECONDS_PER_DAY)
        os.utime(path, (modified, modified))
        return path

    def cleanup(self, forwarded_days=90, failed_days=90, dry_run=False):
        return ipa_redactor.cleanup_expired_archives(
            self.logs_dir,
            self.output,
            self.errors,
            forwarded_days,
            failed_days,
            dry_run=dry_run,
            now=self.now,
        )

    def test_removes_only_expired_outcome_archives(self):
        old_forwarded = self.create_file("old.tar.gz.forwarded", 91)
        old_failed = self.create_file("old.tar.gz.failed", 91)
        fresh_forwarded = self.create_file("fresh.tar.gz.forwarded", 89)
        unprocessed = self.create_file("unprocessed.tar.gz", 365)
        unrelated = self.create_file("unrelated.forwarded", 365)

        self.assertEqual(self.cleanup(), 2)

        self.assertFalse(old_forwarded.exists())
        self.assertFalse(old_failed.exists())
        self.assertTrue(fresh_forwarded.exists())
        self.assertTrue(unprocessed.exists())
        self.assertTrue(unrelated.exists())
        self.assertEqual(self.errors.getvalue(), "")

    def test_zero_retention_disables_deletion(self):
        old_forwarded = self.create_file("old.tar.gz.forwarded", 365)
        old_failed = self.create_file("old.tar.gz.failed", 365)

        self.assertEqual(self.cleanup(forwarded_days=0, failed_days=0), 0)
        self.assertTrue(old_forwarded.exists())
        self.assertTrue(old_failed.exists())

    def test_retention_starts_when_archive_is_marked_with_outcome(self):
        outcome_paths = []
        for outcome in ("forwarded", "failed"):
            claimed = self.logs_dir / "{}.tar.gz.processing".format(outcome)
            claimed.write_bytes(b"archive")
            old_time = self.now - (365 * ipa_redactor.SECONDS_PER_DAY)
            os.utime(claimed, (old_time, old_time))

            outcome_path = ipa_redactor.mark_outcome(
                claimed,
                outcome,
                outcome_time=self.now,
            )
            outcome_paths.append(outcome_path)
            self.assertEqual(outcome_path.stat().st_mtime, self.now)

        self.assertEqual(
            ipa_redactor.cleanup_expired_archives(
                self.logs_dir,
                self.output,
                self.errors,
                90,
                90,
                dry_run=False,
                now=self.now + (89 * ipa_redactor.SECONDS_PER_DAY),
            ),
            0,
        )
        self.assertTrue(all(path.exists() for path in outcome_paths))

        self.assertEqual(
            ipa_redactor.cleanup_expired_archives(
                self.logs_dir,
                self.output,
                self.errors,
                90,
                90,
                dry_run=False,
                now=self.now + (91 * ipa_redactor.SECONDS_PER_DAY),
            ),
            2,
        )
        self.assertTrue(all(not path.exists() for path in outcome_paths))

    def test_symlink_with_outcome_suffix_is_ignored(self):
        target = self.create_file("target", 365)
        link = self.logs_dir / "link.tar.gz.forwarded"
        link.symlink_to(target)

        self.assertEqual(self.cleanup(), 0)
        self.assertTrue(link.is_symlink())
        self.assertTrue(target.exists())

    def test_failed_quarantine_uses_failed_retention(self):
        old_quarantine = self.create_file(
            "old.tar.gz.failed.20260925T120000Z", 91
        )
        unrelated = self.create_file("old.tar.gz.failed.invalid", 365)

        self.assertEqual(self.cleanup(), 1)

        self.assertFalse(old_quarantine.exists())
        self.assertTrue(unrelated.exists())


    def test_file_removed_by_another_process_is_skipped_silently(self):
        self.create_file("old.tar.gz.forwarded", 91)
        with mock.patch.object(Path, "unlink", side_effect=FileNotFoundError):
            removed = self.cleanup()
        self.assertEqual(removed, 0)
        self.assertEqual(self.errors.getvalue(), "")
        self.assertNotIn("removed expired", self.output.getvalue())

    def test_unlink_failure_is_reported_and_other_files_are_still_removed(self):
        stuck = self.create_file("a-old.tar.gz.forwarded", 91)
        removable = self.create_file("b-old.tar.gz.forwarded", 91)
        real_unlink = Path.unlink

        def flaky_unlink(path, *args, **kwargs):
            if path.name.startswith("a-"):
                raise PermissionError("synthetic denial")
            return real_unlink(path, *args, **kwargs)

        with mock.patch.object(Path, "unlink", flaky_unlink):
            removed = self.cleanup()

        self.assertEqual(removed, 1)
        self.assertTrue(stuck.exists())
        self.assertFalse(removable.exists())
        failures = structured_records(self.errors.getvalue())
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]["event"], "retention_cleanup_failed")
        self.assertEqual(failures[0]["error_code"], "filesystem_error")
        self.assertEqual(failures[0]["outcome"], "forwarded")
        self.assertNotIn("synthetic denial", self.errors.getvalue())

    def test_forwarded_and_failed_retention_are_independent(self):
        forwarded = self.create_file("a.tar.gz.forwarded", 91)
        failed = self.create_file("b.tar.gz.failed", 91)
        self.assertEqual(self.cleanup(forwarded_days=90, failed_days=365), 1)
        self.assertFalse(forwarded.exists())
        self.assertTrue(failed.exists())

        self.assertEqual(self.cleanup(forwarded_days=365, failed_days=90), 1)
        self.assertFalse(failed.exists())

    def test_age_boundary_is_inclusive_at_exactly_the_retention_period(self):
        at_limit = self.create_file("limit.tar.gz.forwarded", 90)
        just_inside = self.create_file("inside.tar.gz.forwarded", 89.99)
        self.assertEqual(self.cleanup(forwarded_days=90), 1)
        self.assertFalse(at_limit.exists())
        self.assertTrue(just_inside.exists())

    def test_unrelated_names_are_never_deleted(self):
        names = (
            "bundle.tar.gz",
            "bundle.tar.gz.processing",
            "bundle.forwarded",
            "bundle.failed",
            "bundle.tar.gz.forwarded.bak",
            "bundle.tar.gz.failed.notatimestamp",
            "bundle.tar.gz.failed.20260925T120000",
            "bundle.tar.gz.failed.20260925T120000Zextra",
            "notes.txt",
        )
        paths = [self.create_file(name, 3650) for name in names]
        self.assertEqual(self.cleanup(forwarded_days=1, failed_days=1), 0)
        self.assertTrue(all(path.exists() for path in paths))

    def test_directory_with_outcome_name_is_ignored(self):
        directory = self.logs_dir / "dir.tar.gz.forwarded"
        directory.mkdir()
        modified = self.now - (365 * ipa_redactor.SECONDS_PER_DAY)
        os.utime(directory, (modified, modified))
        self.assertEqual(self.cleanup(), 0)
        self.assertTrue(directory.is_dir())

    def test_numbered_quarantine_names_are_eligible_for_failed_retention(self):
        quarantines = [
            self.create_file("old.tar.gz.failed.20260925T120000Z", 91),
            self.create_file("old.tar.gz.failed.20260925T120000Z.1", 91),
            self.create_file("old.tar.gz.failed.20260925T120000Z.12", 91),
        ]
        self.assertEqual(self.cleanup(failed_days=90), 3)
        self.assertTrue(all(not path.exists() for path in quarantines))

    def test_dry_run_reports_each_eligible_file_and_deletes_nothing(self):
        paths = [
            self.create_file("a.tar.gz.forwarded", 91),
            self.create_file("b.tar.gz.failed", 91),
            self.create_file("fresh.tar.gz.forwarded", 1),
        ]
        self.assertEqual(self.cleanup(dry_run=True), 0)
        self.assertTrue(all(path.exists() for path in paths))
        output = self.output.getvalue()
        self.assertIn("would remove expired forwarded archive", output)
        self.assertIn("would remove expired failed archive", output)
        self.assertEqual(output.count("would remove"), 2)
        self.assertIn("retention dry-run: would remove", output)
        self.assertEqual(self.errors.getvalue(), "")


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.logs_dir = Path(self.temp_dir.name)
        self.output = io.StringIO()
        self.errors = io.StringIO()
        self.stability_observations = {}
        self.retry_state = {}

    def tearDown(self):
        self.temp_dir.cleanup()

    def bundle_path(self, context=INSTANCE_UUID):
        return self.logs_dir / (
            "{}_node1_{}_2026-09-03-13-14-50.tar.gz".format(
                NODE_UUID, context
            )
        )

    def create_bundle(self, members, context=INSTANCE_UUID):
        path = self.bundle_path(context)
        with tarfile.open(path, "w:gz") as archive:
            for name, content in members:
                add_bytes(archive, name, content)
        return path

    def process(
        self,
        max_member_bytes=1024 * 1024,
        max_total_output_bytes=2 * 1024 * 1024,
        max_total_archive_bytes=4 * 1024 * 1024,
        max_archive_bytes=32 * 1024 * 1024,
        max_line_bytes=1024 * 1024,
        max_output_lines=100_000,
        max_forwarded_bytes=4 * 1024 * 1024,
        stability_seconds=0,
        scan_time=None,
        max_processing_attempts=3,
        retry_backoff_seconds=60.0,
    ):
        return ipa_redactor.process_available(
            self.logs_dir,
            self.output,
            self.errors,
            max_archive_members=32,
            max_archive_bytes=max_archive_bytes,
            max_total_archive_bytes=max_total_archive_bytes,
            max_member_bytes=max_member_bytes,
            max_line_bytes=max_line_bytes,
            max_total_output_bytes=max_total_output_bytes,
            max_output_lines=max_output_lines,
            max_forwarded_bytes=max_forwarded_bytes,
            stability_observations=self.stability_observations,
            stability_seconds=stability_seconds,
            scan_time=scan_time,
            retry_state=self.retry_state,
            max_processing_attempts=max_processing_attempts,
            retry_backoff_seconds=retry_backoff_seconds,
        )

    def assert_failure_code(self, expected):
        failures = [
            record
            for record in lifecycle_records(self.output.getvalue())
            if record["event"] == "archive_failed"
        ]
        self.assertGreater(len(failures), 0)
        self.assertEqual(failures[-1]["error_code"], expected)
        self.assertEqual(failures[-1]["status"], "failed")

    def test_streams_redacted_logs_and_marks_forwarded(self):
        original = self.create_bundle(
            [
                ("journal", "agent_token = journal-secret\nnormal journal line\n"),
                ("dmesg", "Command line: rootpwd=dmesg-secret console=ttyS0\n"),
                ("ignored", "must not be emitted\n"),
            ]
        )

        self.assertEqual(self.process(), 1)

        result = self.output.getvalue()
        records = lifecycle_records(result)
        self.assertEqual(
            [record["event"] for record in records],
            ["archive_start", "archive_complete"],
        )
        archive_id = ipa_redactor.archive_id_for(original)
        self.assertEqual(len(archive_id), ipa_redactor.ARCHIVE_ID_HEX_LENGTH)
        self.assertEqual(records[0]["archive_id"], archive_id)
        self.assertEqual(records[1]["archive_id"], archive_id)
        self.assertEqual(records[0]["archive_name"], original.name)
        self.assertEqual(records[0]["status"], "processing")
        self.assertEqual(records[1]["status"], "processed")
        self.assertNotIn("archive_name", records[1])
        self.assertEqual(result.count(original.name), 1)
        self.assertEqual(records[0]["attempt_id"], records[1]["attempt_id"])
        self.assertNotIn("error_code", records[0])
        self.assertNotIn("error_code", records[1])
        self.assertIn("[ipa-log-redactor]", result)
        self.assertNotIn("ironic-python-agent-log-sidecar", result)
        prefix = "[node1]"
        self.assertIn(prefix, result)
        self.assertIn("agent_token=REDACTED", result)
        self.assertIn("rootpwd=REDACTED", result)
        self.assertIn("normal journal line", result)
        content_lines = [
            line
            for line in result.splitlines()
            if line.startswith(prefix + " ")
        ]
        self.assertGreater(len(content_lines), 0)
        for line in content_lines:
            self.assertIn("[archive={}]".format(archive_id), line)
            self.assertNotIn(original.name, line)
            self.assertNotIn(records[0]["attempt_id"], line)
        self.assertIn("[archive={}] [journal] agent_token=REDACTED".format(archive_id), result)
        self.assertIn("[archive={}] [journal] normal journal line".format(archive_id), result)
        self.assertIn(
            "[archive={}] [dmesg] Command line: rootpwd=REDACTED".format(archive_id),
            result,
        )
        self.assertIn("=== journal ===", result)
        self.assertIn("=== dmesg ===", result)
        self.assertNotIn("journal-secret", result)
        self.assertNotIn("dmesg-secret", result)
        self.assertNotIn("must not be emitted", result)
        self.assertFalse(original.exists())
        self.assertTrue(Path(str(original) + ".forwarded").exists())

    def test_cleaning_context_is_printed_once_in_archive_name(self):
        original = self.create_bundle([("journal", "cleaning log\n")], context="cleaning")
        self.process()
        result = self.output.getvalue()
        records = lifecycle_records(result)
        archive_id = ipa_redactor.archive_id_for(original)
        self.assertIn("_node1_cleaning_", records[0]["archive_name"])
        self.assertIn(
            "[node1] [archive={}] [journal] cleaning log".format(
                archive_id
            ),
            result,
        )
        self.assertNotIn("[node1_cleaning]", result)
        self.assertTrue(Path(str(original) + ".forwarded").exists())

    def test_streams_expanded_redaction_formats(self):
        synthetic_log = (
            "Authorization: Bearer synthetic-token-value\n"
            "https://fake-user:fake-password@example.invalid/image\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "synthetic-private-key-content\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeMaterial "
            "fake@example.invalid\n"
            "safe line\n"
        )
        self.create_bundle([("journal", synthetic_log)])

        self.assertEqual(self.process(), 1)

        result = self.output.getvalue()
        self.assertNotIn("synthetic-token-value", result)
        self.assertNotIn("fake-password", result)
        self.assertNotIn("synthetic-private-key-content", result)
        self.assertNotIn("FakeMaterial", result)
        self.assertIn("Authorization: REDACTED", result)
        self.assertIn("https://REDACTED@example.invalid/image", result)
        self.assertIn("[REDACTED PRIVATE KEY]", result)
        self.assertIn("SSH_PUBLIC_KEY_REDACTED", result)
        self.assertIn("safe line", result)

    def test_missing_journal_is_marked_failed(self):
        original = self.create_bundle([("dmesg", "safe\n")])
        self.process()
        self.assertTrue(Path(str(original) + ".failed").exists())
        records = lifecycle_records(self.output.getvalue())
        self.assertEqual(
            [record["event"] for record in records],
            ["archive_start", "archive_failed"],
        )
        self.assertEqual(records[0]["attempt_id"], records[1]["attempt_id"])
        self.assertEqual(records[0]["archive_id"], records[1]["archive_id"])
        self.assert_failure_code("missing_journal")

    def test_oversized_selected_member_is_marked_failed(self):
        original = self.create_bundle([("journal", "12345")])
        self.process(max_member_bytes=4)
        self.assertTrue(Path(str(original) + ".failed").exists())
        self.assert_failure_code("member_too_large")

    def test_oversized_line_is_marked_failed(self):
        original = self.create_bundle(
            [("journal", "short line\n" + ("x" * 17) + "\nnot forwarded\n")]
        )

        self.process(max_line_bytes=16)

        self.assertFalse(original.exists())
        self.assertTrue(Path(str(original) + ".failed").exists())
        self.assertNotIn("not forwarded", self.output.getvalue())
        self.assert_failure_code("line_too_large")

    def test_output_line_limit_includes_section_and_content_records(self):
        original = self.create_bundle(
            [("journal", "first line\nsecond line\nthird line\n")]
        )

        self.process(max_output_lines=3)

        self.assertTrue(Path(str(original) + ".failed").exists())
        self.assertIn("first line", self.output.getvalue())
        self.assertIn("second line", self.output.getvalue())
        self.assertNotIn("third line", self.output.getvalue())
        self.assert_failure_code("too_many_output_lines")

    def test_forwarded_byte_limit_counts_prefix_and_section_records(self):
        original = self.create_bundle([("journal", "x\n")])
        archive_id = ipa_redactor.archive_id_for(original)
        section = (
            "{} [archive_id={}] "
            "===================== journal =====================\n"
        ).format(
            ipa_redactor.REDACTOR_TAG, archive_id
        )

        self.process(max_forwarded_bytes=len(section.encode("utf-8")))

        self.assertTrue(Path(str(original) + ".failed").exists())
        self.assertIn("=== journal ===", self.output.getvalue())
        self.assertNotIn("[journal] x\n", self.output.getvalue())
        self.assert_failure_code("forwarded_output_too_large")

    def test_combined_uncompressed_size_limit_marks_archive_failed(self):
        original = self.create_bundle([("journal", "1234"), ("dmesg", "5678")])

        self.process(max_member_bytes=8, max_total_output_bytes=7)

        self.assertTrue(Path(str(original) + ".failed").exists())
        self.assertEqual(
            [record["event"] for record in lifecycle_records(self.output.getvalue())],
            ["archive_start", "archive_failed"],
        )
        self.assert_failure_code("total_output_too_large")

    def test_total_uncompressed_archive_limit_includes_ignored_members(self):
        original = self.create_bundle([("journal", "1234"), ("ignored", "5678")])

        self.process(max_total_archive_bytes=7)

        self.assertTrue(Path(str(original) + ".failed").exists())
        self.assertEqual(
            [record["event"] for record in lifecycle_records(self.output.getvalue())],
            ["archive_start", "archive_failed"],
        )
        self.assert_failure_code("total_archive_too_large")

    def test_non_gzip_tar_archive_is_marked_failed(self):
        original = self.bundle_path()
        with tarfile.open(original, "w") as archive:
            add_bytes(archive, "journal", "synthetic log\n")

        self.process()

        self.assertTrue(Path(str(original) + ".failed").exists())
        self.assertEqual(
            [record["event"] for record in lifecycle_records(self.output.getvalue())],
            ["archive_start", "archive_failed"],
        )
        self.assert_failure_code("invalid_archive")

    def test_raw_exception_text_is_not_written_to_diagnostics(self):
        original = self.create_bundle([("journal", "safe\n")])

        with mock.patch.object(
            ipa_redactor.tarfile,
            "open",
            side_effect=tarfile.ReadError("synthetic-secret\nforged-record"),
        ):
            self.process()

        diagnostics = structured_records(self.errors.getvalue())
        self.assertTrue(Path(str(original) + ".failed").exists())
        self.assertNotIn("synthetic-secret", self.errors.getvalue())
        self.assertNotIn("forged-record", self.errors.getvalue())
        self.assertEqual(diagnostics[-1]["event"], "archive_processing_failed")
        self.assertEqual(diagnostics[-1]["error_code"], "invalid_archive")

    def test_completion_is_not_emitted_when_forwarded_transition_fails(self):
        original = self.create_bundle([("journal", "safe\n")])
        real_mark_outcome = ipa_redactor.mark_outcome

        def fail_forwarded(path, outcome, outcome_time=None):
            if outcome == "forwarded":
                raise OSError("synthetic-secret\nforged-record")
            return real_mark_outcome(path, outcome, outcome_time)

        with mock.patch.object(
            ipa_redactor,
            "mark_outcome",
            side_effect=fail_forwarded,
        ):
            self.process()

        records = lifecycle_records(self.output.getvalue())
        self.assertEqual(
            [record["event"] for record in records],
            ["archive_start", "archive_failed"],
        )
        self.assertEqual(records[-1]["error_code"], "filesystem_error")
        self.assertTrue(Path(str(original) + ".failed").exists())
        self.assertFalse(Path(str(original) + ".forwarded").exists())
        self.assertNotIn("synthetic-secret", self.errors.getvalue())
        self.assertNotIn("forged-record", self.errors.getvalue())

    def test_existing_outcome_quarantines_incoming_archive(self):
        original = self.create_bundle([("journal", "must not be forwarded\n")])
        existing = Path(str(original) + ".forwarded")
        existing.write_bytes(b"existing outcome")

        with mock.patch.object(ipa_redactor.time, "time", return_value=1_797_595_200.0):
            self.process()

        quarantines = list(self.logs_dir.glob("*.tar.gz.failed.*"))
        self.assertEqual(existing.read_bytes(), b"existing outcome")
        self.assertFalse(original.exists())
        self.assertEqual(len(quarantines), 1)
        self.assertEqual(
            [record["event"] for record in lifecycle_records(self.output.getvalue())],
            ["archive_start", "archive_failed"],
        )
        diagnostics = structured_records(self.errors.getvalue())
        self.assertEqual(diagnostics[-1]["event"], "archive_quarantined")
        self.assertIn("quarantine_name", diagnostics[-1])
        self.assert_failure_code("outcome_collision")

    def test_existing_failed_outcome_quarantines_incoming_archive(self):
        original = self.create_bundle([("journal", "must not be forwarded\n")])
        existing = Path(str(original) + ".failed")
        existing.write_bytes(b"existing failure")

        self.process()

        quarantines = list(self.logs_dir.glob("*.tar.gz.failed.*"))
        self.assertEqual(existing.read_bytes(), b"existing failure")
        self.assertFalse(original.exists())
        self.assertEqual(len(quarantines), 1)
        self.assertEqual(
            [record["event"] for record in lifecycle_records(self.output.getvalue())],
            ["archive_start", "archive_failed"],
        )
        self.assertEqual(
            structured_records(self.errors.getvalue())[-1]["event"],
            "archive_quarantined",
        )
        self.assert_failure_code("outcome_collision")

    def test_retry_keeps_archive_id_and_uses_a_new_attempt_id(self):
        original = self.create_bundle([("dmesg", "missing journal\n")])
        self.process()
        Path(str(original) + ".failed").unlink()

        self.create_bundle([("dmesg", "missing journal again\n")])
        self.process()

        records = lifecycle_records(self.output.getvalue())
        starts = [record for record in records if record["event"] == "archive_start"]
        failures = [record for record in records if record["event"] == "archive_failed"]
        self.assertEqual(len(starts), 2)
        self.assertEqual(len(failures), 2)
        self.assertEqual(starts[0]["archive_id"], starts[1]["archive_id"])
        self.assertNotEqual(starts[0]["attempt_id"], starts[1]["attempt_id"])

    def count_starts(self):
        return sum(
            1
            for record in lifecycle_records(self.output.getvalue())
            if record["event"] == "archive_start"
        )

    def test_stuck_outcome_transition_backs_off_and_stops_after_limit(self):
        original = self.create_bundle([("journal", "stuck journal line\n")])
        claimed = Path(str(original) + ".processing")

        with mock.patch.object(
            ipa_redactor, "move_without_overwrite", side_effect=PermissionError("denied")
        ):
            # Attempt 1 at t=0 sets a 60 second backoff.
            self.process(scan_time=0)
            self.assertEqual(self.count_starts(), 1)
            for skipped_time in (1, 30, 59):
                self.process(scan_time=skipped_time)
            self.assertEqual(self.count_starts(), 1)

            # Attempt 2 at t=60 doubles the backoff to 120 seconds.
            self.process(scan_time=60)
            self.assertEqual(self.count_starts(), 2)
            for skipped_time in (61, 179):
                self.process(scan_time=skipped_time)
            self.assertEqual(self.count_starts(), 2)
            self.assertNotIn("archive_retry_limit_reached", self.errors.getvalue())

            # Attempt 3 reaches the limit; later scans never process it again.
            self.process(scan_time=180)
            self.assertEqual(self.count_starts(), 3)
            for later_time in (181, 1_000, 100_000):
                self.process(scan_time=later_time)

        self.assertEqual(self.count_starts(), 3)
        self.assertEqual(self.output.getvalue().count("[journal] stuck journal line"), 3)
        self.assertEqual(self.errors.getvalue().count("archive_retry_limit_reached"), 1)
        self.assertTrue(claimed.exists())
        self.assertEqual(
            self.retry_state[claimed][0],
            3,
        )

    def test_stuck_outcome_transition_recovers_when_filesystem_recovers(self):
        original = self.create_bundle([("journal", "recovering line\n")])
        claimed = Path(str(original) + ".processing")

        with mock.patch.object(
            ipa_redactor, "move_without_overwrite", side_effect=PermissionError("denied")
        ):
            self.process(scan_time=0)
        self.assertTrue(claimed.exists())
        self.assertIn(claimed, self.retry_state)

        # Before the backoff expires the healthy filesystem is not tried yet.
        self.process(scan_time=30)
        self.assertTrue(claimed.exists())

        self.process(scan_time=60)
        self.assertFalse(claimed.exists())
        self.assertTrue(Path(str(original) + ".forwarded").exists())
        self.assertEqual(self.retry_state, {})
        self.assertEqual(self.count_starts(), 2)

    def test_retry_state_is_dropped_when_stuck_archive_disappears(self):
        original = self.create_bundle([("journal", "vanishing line\n")])
        claimed = Path(str(original) + ".processing")

        with mock.patch.object(
            ipa_redactor, "move_without_overwrite", side_effect=PermissionError("denied")
        ):
            self.process(scan_time=0)
        self.assertIn(claimed, self.retry_state)

        claimed.unlink()
        self.process(scan_time=1)
        self.assertEqual(self.retry_state, {})

    def test_successful_archives_leave_no_retry_state(self):
        self.create_bundle([("journal", "normal line\n")])
        self.process(scan_time=0)
        self.assertEqual(self.retry_state, {})

    def test_oversized_compressed_archive_is_marked_failed_before_opening(self):
        original = self.create_bundle([("journal", "synthetic log\n")])
        archive_size = original.stat().st_size

        self.process(max_archive_bytes=archive_size - 1)

        self.assertFalse(original.exists())
        self.assertTrue(Path(str(original) + ".failed").exists())
        self.assert_failure_code("archive_too_large")

    def test_non_regular_selected_member_is_marked_failed(self):
        original = self.bundle_path()
        with tarfile.open(original, "w:gz") as archive:
            member = tarfile.TarInfo("journal")
            member.type = tarfile.SYMTYPE
            member.linkname = "/etc/passwd"
            archive.addfile(member)
        self.process()
        self.assertTrue(Path(str(original) + ".failed").exists())
        self.assert_failure_code("unsafe_member_type")

    def test_invalid_filename_has_controlled_failure_code(self):
        original = self.logs_dir / (
            "{}_compute 2_cleaning_2026-09-03-13-14-50.tar.gz".format(NODE_UUID)
        )
        with tarfile.open(original, "w:gz") as archive:
            add_bytes(archive, "journal", "safe log\n")

        self.process()

        self.assertTrue(Path(str(original) + ".failed").exists())
        self.assert_failure_code("invalid_filename")

    def test_interrupted_processing_file_is_recovered(self):
        original = self.create_bundle([("journal", "recovered\n")])
        processing = Path(str(original) + ".processing")
        original.rename(processing)
        self.process()
        self.assertFalse(processing.exists())
        self.assertTrue(Path(str(original) + ".forwarded").exists())

    def test_new_archive_must_be_unchanged_across_scans_for_stability_window(self):
        original = self.create_bundle([("journal", "stable log\n")])

        self.assertEqual(self.process(stability_seconds=60, scan_time=100), 0)
        self.assertTrue(original.exists())

        metadata = original.stat()
        os.utime(
            original,
            ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1),
        )
        self.assertEqual(self.process(stability_seconds=60, scan_time=130), 0)
        self.assertEqual(self.process(stability_seconds=60, scan_time=189), 0)
        self.assertTrue(original.exists())

        self.assertEqual(self.process(stability_seconds=60, scan_time=190), 1)
        self.assertFalse(original.exists())
        self.assertTrue(Path(str(original) + ".forwarded").exists())

    def test_archive_size_change_restarts_stability_window(self):
        original = self.create_bundle([("journal", "changing log\n")])

        self.assertEqual(self.process(stability_seconds=60, scan_time=100), 0)
        original.write_bytes(original.read_bytes() + b"synthetic-incomplete-data")

        self.assertEqual(self.process(stability_seconds=60, scan_time=160), 0)
        self.assertTrue(original.exists())

    def test_interrupted_processing_file_does_not_wait_for_stability(self):
        original = self.create_bundle([("journal", "recovered immediately\n")])
        processing = Path(str(original) + ".processing")
        original.rename(processing)

        self.assertEqual(self.process(stability_seconds=60, scan_time=100), 1)
        self.assertTrue(Path(str(original) + ".forwarded").exists())


    # Direct processing of one claimed archive.

    def claim(self, original):
        claimed = Path(str(original) + ".processing")
        original.rename(claimed)
        return claimed

    def run_claimed(self, claimed, output=None, errors=None, **overrides):
        limits = dict(
            max_archive_members=32,
            max_archive_bytes=32 * 1024 * 1024,
            max_total_archive_bytes=4 * 1024 * 1024,
            max_member_bytes=1024 * 1024,
            max_line_bytes=1024 * 1024,
            max_total_output_bytes=2 * 1024 * 1024,
            max_output_lines=100_000,
            max_forwarded_bytes=4 * 1024 * 1024,
        )
        limits.update(overrides)
        return ipa_redactor.process_claimed_archive(
            claimed,
            self.output if output is None else output,
            self.errors if errors is None else errors,
            **limits
        )

    def create_raw_bundle(self, members, context=INSTANCE_UUID):
        """Create a bundle from (name, bytes) pairs, allowing duplicates."""
        path = self.bundle_path(context)
        with tarfile.open(path, "w:gz") as archive:
            for name, payload in members:
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        return path

    def section_order(self):
        return [
            line.split("=====================")[1].strip()
            for line in self.output.getvalue().splitlines()
            if line.startswith(ipa_redactor.REDACTOR_TAG + " [archive_id=")
        ]

    def event_names(self, text):
        return [record["event"] for record in structured_records(text)]

    def test_broken_pipe_propagates_and_leaves_the_archive_claimed(self):
        claimed = self.claim(self.create_bundle([("journal", "line\n")]))

        class ClosedPipe(io.StringIO):
            def write(self, text):
                raise BrokenPipeError()

        with self.assertRaises(BrokenPipeError):
            self.run_claimed(claimed, output=ClosedPipe())

        self.assertTrue(claimed.exists())
        self.assertEqual(list(self.logs_dir.glob("*.forwarded")), [])
        self.assertEqual(list(self.logs_dir.glob("*.failed*")), [])

    def test_collision_during_final_transition_is_quarantined_without_completion(self):
        claimed = self.claim(self.create_bundle([("journal", "kept line\n")]))
        real_move = ipa_redactor.move_without_overwrite
        calls = []

        def racing_move(source, destination):
            calls.append(destination.name)
            if len(calls) == 1:
                raise ipa_redactor.OutcomeCollisionError("synthetic race")
            return real_move(source, destination)

        with mock.patch.object(ipa_redactor, "move_without_overwrite", racing_move):
            result = self.run_claimed(claimed)

        self.assertFalse(result)
        self.assertFalse(claimed.exists())
        self.assertEqual(len(list(self.logs_dir.glob("*.tar.gz.failed.*"))), 1)
        self.assertEqual(list(self.logs_dir.glob("*.forwarded")), [])
        self.assertEqual(
            self.event_names(self.output.getvalue()),
            ["archive_start", "archive_failed"],
        )
        self.assert_failure_code("outcome_collision")
        self.assertEqual(
            self.event_names(self.errors.getvalue()), ["archive_quarantined"]
        )

    def test_quarantine_failure_during_final_transition_is_reported(self):
        claimed = self.claim(self.create_bundle([("journal", "line\n")]))
        with (
            mock.patch.object(
                ipa_redactor,
                "move_without_overwrite",
                side_effect=ipa_redactor.OutcomeCollisionError("synthetic race"),
            ),
            mock.patch.object(
                ipa_redactor, "quarantine_archive", side_effect=PermissionError("denied")
            ),
        ):
            result = self.run_claimed(claimed)

        self.assertFalse(result)
        self.assertTrue(claimed.exists())
        self.assertIn("outcome_transition_failed", self.errors.getvalue())
        self.assert_failure_code("outcome_collision")
        self.assertNotIn("denied", self.errors.getvalue())

    def test_collision_while_marking_failure_quarantines_and_keeps_original_code(self):
        original = self.bundle_path()
        original.write_bytes(b"this is not a gzip tar archive")
        claimed = self.claim(original)
        real_move = ipa_redactor.move_without_overwrite
        calls = []

        def racing_move(source, destination):
            calls.append(destination.name)
            if len(calls) == 1:
                raise ipa_redactor.OutcomeCollisionError("synthetic race")
            return real_move(source, destination)

        with mock.patch.object(ipa_redactor, "move_without_overwrite", racing_move):
            result = self.run_claimed(claimed)

        self.assertFalse(result)
        self.assertFalse(claimed.exists())
        self.assertEqual(len(list(self.logs_dir.glob("*.tar.gz.failed.*"))), 1)
        self.assert_failure_code("invalid_archive")
        self.assertEqual(
            self.event_names(self.errors.getvalue()),
            ["archive_processing_failed", "archive_quarantined"],
        )

    def test_quarantine_failure_while_marking_failure_is_reported(self):
        original = self.bundle_path()
        original.write_bytes(b"this is not a gzip tar archive")
        claimed = self.claim(original)
        with (
            mock.patch.object(
                ipa_redactor,
                "move_without_overwrite",
                side_effect=ipa_redactor.OutcomeCollisionError("synthetic race"),
            ),
            mock.patch.object(
                ipa_redactor, "quarantine_archive", side_effect=PermissionError("denied")
            ),
        ):
            result = self.run_claimed(claimed)

        self.assertFalse(result)
        self.assertTrue(claimed.exists())
        self.assertEqual(
            self.event_names(self.errors.getvalue()),
            ["archive_processing_failed", "outcome_transition_failed"],
        )
        self.assert_failure_code("invalid_archive")

    def test_archive_that_disappears_is_reported_as_filesystem_error(self):
        missing = self.logs_dir / (self.bundle_path().name + ".processing")
        result = self.run_claimed(missing)

        self.assertFalse(result)
        self.assert_failure_code("filesystem_error")
        self.assertEqual(
            self.event_names(self.errors.getvalue()),
            ["archive_processing_failed", "outcome_transition_failed"],
        )

    def test_sections_are_emitted_in_fixed_order_regardless_of_tar_order(self):
        self.create_bundle(
            [
                ("dmesg", "d\n"),
                ("lsblk", "l\n"),
                ("ip_addr", "i\n"),
                ("journal", "j\n"),
            ]
        )
        self.assertEqual(self.process(), 1)
        self.assertEqual(self.section_order(), ["journal", "ip_addr", "lsblk", "dmesg"])

    def test_optional_members_are_skipped_when_absent(self):
        self.create_bundle([("journal", "j\n"), ("lsblk", "l\n")])
        self.assertEqual(self.process(), 1)
        self.assertEqual(self.section_order(), ["journal", "lsblk"])

    def test_only_exact_member_names_are_selected(self):
        decoys = [
            "./journal",
            "dir/journal",
            "Journal",
            "journal.txt",
            " journal",
            "journal/",
            "../journal",
            "/journal",
        ]
        original = self.create_raw_bundle(
            [(name, b"decoy-content\n") for name in decoys]
        )
        self.assertEqual(self.process(), 1)
        self.assert_failure_code("missing_journal")
        self.assertNotIn("decoy-content", self.output.getvalue())
        self.assertTrue(Path(str(original) + ".failed").exists())

    def test_decoy_members_are_ignored_when_a_real_journal_is_present(self):
        self.create_raw_bundle(
            [
                ("./journal", b"decoy-content\n"),
                ("journal", b"real-content\n"),
                ("dir/dmesg", b"decoy-dmesg\n"),
            ]
        )
        self.assertEqual(self.process(), 1)
        self.assertIn("real-content", self.output.getvalue())
        self.assertNotIn("decoy", self.output.getvalue())
        self.assertEqual(self.section_order(), ["journal"])

    def test_duplicate_selected_member_is_rejected(self):
        original = self.create_raw_bundle(
            [("journal", b"first\n"), ("journal", b"second\n")]
        )
        self.assertEqual(self.process(), 1)
        self.assert_failure_code("duplicate_member")
        self.assertNotIn("first", self.output.getvalue())
        self.assertTrue(Path(str(original) + ".failed").exists())

    def test_too_many_members_is_rejected(self):
        claimed = self.claim(
            self.create_raw_bundle(
                [("journal", b"j\n"), ("a", b"x"), ("b", b"y"), ("c", b"z")]
            )
        )
        self.assertFalse(self.run_claimed(claimed, max_archive_members=3))
        self.assert_failure_code("too_many_members")

    def test_member_count_limit_allows_exactly_the_maximum(self):
        claimed = self.claim(
            self.create_raw_bundle([("journal", b"j\n"), ("a", b"x"), ("b", b"y")])
        )
        self.assertTrue(self.run_claimed(claimed, max_archive_members=3))

    def test_empty_journal_member_is_forwarded_with_only_a_section_header(self):
        original = self.create_bundle([("journal", "")])
        self.assertEqual(self.process(), 1)
        self.assertEqual(self.section_order(), ["journal"])
        content = [
            line
            for line in self.output.getvalue().splitlines()
            if line.startswith("[node1]")
        ]
        self.assertEqual(content, [])
        self.assertTrue(Path(str(original) + ".forwarded").exists())

    def test_content_line_prefix_has_the_documented_exact_format(self):
        original = self.create_bundle([("journal", "hello world\n")])
        self.assertEqual(self.process(), 1)
        archive_id = ipa_redactor.archive_id_for(original)
        self.assertIn(
            "[node1] [archive={}] [journal] hello world\n".format(archive_id),
            self.output.getvalue(),
        )

    def test_missing_trailing_newline_is_added_and_crlf_is_preserved(self):
        self.create_raw_bundle([("journal", b"first\r\nsecond\r\nlast no newline")])
        self.assertEqual(self.process(), 1)
        output = self.output.getvalue()
        self.assertIn("[journal] first\r\n", output)
        self.assertIn("[journal] second\r\n", output)
        self.assertIn("[journal] last no newline\n[ipa-log-redactor]", output)

    def test_invalid_utf8_is_replaced_without_failing_the_archive(self):
        original = self.create_raw_bundle([("journal", b"bad \xff\xfe bytes\n")])
        self.assertEqual(self.process(), 1)
        self.assertIn("[journal] bad \ufffd\ufffd bytes\n", self.output.getvalue())
        self.assertTrue(Path(str(original) + ".forwarded").exists())

    def test_unterminated_private_key_block_does_not_hide_the_next_member(self):
        self.create_bundle(
            [
                ("journal", "before\n-----BEGIN PRIVATE KEY-----\nsynthetic-body\n"),
                ("dmesg", "dmesg line stays visible\n"),
            ]
        )
        self.assertEqual(self.process(), 1)
        output = self.output.getvalue()
        self.assertIn("[journal] before\n", output)
        self.assertIn("[REDACTED PRIVATE KEY]", output)
        self.assertNotIn("synthetic-body", output)
        self.assertIn("[dmesg] dmesg line stays visible\n", output)

    def test_secrets_are_redacted_in_every_forwarded_member(self):
        self.create_bundle(
            [
                ("journal", "agent_token=SYNTH-journal\n"),
                ("ip_addr", "agent_token=SYNTH-ip\n"),
                ("lsblk", "agent_token=SYNTH-lsblk\n"),
                ("dmesg", "agent_token=SYNTH-dmesg\n"),
            ]
        )
        self.assertEqual(self.process(), 1)
        self.assertNotIn("SYNTH-", self.output.getvalue())
        self.assertEqual(self.output.getvalue().count("agent_token=REDACTED"), 4)

    def test_line_length_limit_is_inclusive_of_the_newline(self):
        exact = self.create_bundle([("journal", "123456789\n")], context=INSTANCE_UUID)
        over = self.create_bundle(
            [("journal", "1234567890\n")],
            context="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )
        self.assertEqual(self.process(max_line_bytes=10), 2)
        self.assertTrue(Path(str(exact) + ".forwarded").exists())
        self.assertTrue(Path(str(over) + ".failed").exists())
        self.assert_failure_code("line_too_large")

    def test_line_without_newline_at_the_limit_is_accepted_and_one_over_is_rejected(self):
        exact = self.create_bundle([("journal", "1234567890")], context=INSTANCE_UUID)
        over = self.create_bundle(
            [("journal", "12345678901")],
            context="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        )
        self.assertEqual(self.process(max_line_bytes=10), 2)
        self.assertTrue(Path(str(exact) + ".forwarded").exists())
        self.assertTrue(Path(str(over) + ".failed").exists())

    def test_two_bundles_in_one_scan_are_processed_independently(self):
        good = self.create_bundle([("journal", "good\n")], context=INSTANCE_UUID)
        bad = self.create_bundle(
            [("dmesg", "no journal\n")],
            context="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        )
        self.assertEqual(self.process(), 2)
        self.assertTrue(Path(str(good) + ".forwarded").exists())
        self.assertTrue(Path(str(bad) + ".failed").exists())
        self.assertEqual(
            sorted(self.event_names(self.output.getvalue())),
            ["archive_complete", "archive_failed", "archive_start", "archive_start"],
        )

    def test_forwarded_archive_keeps_its_original_compressed_bytes(self):
        original = self.create_bundle([("journal", "payload\n")])
        before = original.read_bytes()
        self.assertEqual(self.process(), 1)
        self.assertEqual(Path(str(original) + ".forwarded").read_bytes(), before)

    def test_outcome_refreshes_modification_time_for_retention(self):
        original = self.create_bundle([("journal", "payload\n")])
        old = 1_000_000_000
        os.utime(original, (old, old))
        self.assertEqual(self.process(), 1)
        forwarded = Path(str(original) + ".forwarded")
        self.assertGreater(forwarded.stat().st_mtime, old + 365 * 24 * 3600)

    def test_symlinked_archive_is_never_claimed_or_read(self):
        target_dir = tempfile.TemporaryDirectory()
        self.addCleanup(target_dir.cleanup)
        real = Path(target_dir.name) / "real.tar.gz"
        with tarfile.open(real, "w:gz") as archive:
            add_bytes(archive, "journal", "outside-content\n")
        link = self.bundle_path()
        link.symlink_to(real)

        self.assertEqual(self.process(), 0)
        self.assertTrue(link.is_symlink())
        self.assertNotIn("outside-content", self.output.getvalue())
        self.assertEqual(list(self.logs_dir.glob("*.processing")), [])

    def test_symlinked_processing_file_is_never_read(self):
        target_dir = tempfile.TemporaryDirectory()
        self.addCleanup(target_dir.cleanup)
        real = Path(target_dir.name) / "real.tar.gz"
        with tarfile.open(real, "w:gz") as archive:
            add_bytes(archive, "journal", "outside-content\n")
        link = Path(str(self.bundle_path()) + ".processing")
        link.symlink_to(real)

        self.assertEqual(self.process(), 0)
        self.assertNotIn("outside-content", self.output.getvalue())

    def test_directory_named_like_an_archive_is_ignored(self):
        (self.logs_dir / "folder.tar.gz").mkdir()
        (self.logs_dir / "folder.tar.gz.processing").mkdir()
        self.assertEqual(self.process(), 0)
        self.assertEqual(self.output.getvalue(), "")

    def test_claim_does_not_replace_an_existing_processing_file(self):
        original = self.create_bundle([("journal", "new\n")])
        existing = Path(str(original) + ".processing")
        existing.write_bytes(b"older claim")
        self.assertIsNone(ipa_redactor.claim_archive(original))
        self.assertTrue(original.exists())
        self.assertEqual(existing.read_bytes(), b"older claim")

    def test_claim_of_an_archive_that_vanished_returns_none(self):
        self.assertIsNone(ipa_redactor.claim_archive(self.bundle_path()))

    def test_files_that_vanish_between_listing_and_stat_are_skipped(self):
        missing = self.logs_dir / "gone.tar.gz"
        with mock.patch.object(Path, "glob", return_value=[missing]):
            claimed = list(
                ipa_redactor.discover_claimed_archives(self.logs_dir, {}, 0.0, 100.0)
            )
        self.assertEqual(claimed, [])

    def test_stability_observations_are_dropped_for_vanished_archives(self):
        original = self.create_bundle([("journal", "x\n")])
        self.assertEqual(self.process(stability_seconds=60, scan_time=100), 0)
        self.assertIn(original, self.stability_observations)
        original.unlink()
        self.assertEqual(self.process(stability_seconds=60, scan_time=130), 0)
        self.assertEqual(self.stability_observations, {})

    def test_process_available_works_without_optional_state_arguments(self):
        self.create_bundle([("journal", "x\n")])
        processed = ipa_redactor.process_available(
            self.logs_dir,
            self.output,
            self.errors,
            32,
            32 * 1024 * 1024,
            4 * 1024 * 1024,
            1024 * 1024,
            1024 * 1024,
            2 * 1024 * 1024,
            100_000,
            4 * 1024 * 1024,
            stability_seconds=0,
        )
        self.assertEqual(processed, 1)

    def test_retry_limit_event_is_emitted_exactly_when_the_limit_is_reached(self):
        self.create_bundle([("journal", "stuck\n")])
        with mock.patch.object(
            ipa_redactor, "move_without_overwrite", side_effect=PermissionError("denied")
        ):
            self.process(scan_time=0, max_processing_attempts=2)
            self.assertNotIn("archive_retry_limit_reached", self.errors.getvalue())
            self.process(scan_time=60, max_processing_attempts=2)
            self.assertEqual(
                self.errors.getvalue().count("archive_retry_limit_reached"), 1
            )
            self.process(scan_time=10_000, max_processing_attempts=2)
        self.assertEqual(self.count_starts(), 2)

    def test_retry_backoff_doubles_and_is_capped(self):
        self.create_bundle([("journal", "stuck\n")])
        claimed = Path(str(self.bundle_path()) + ".processing")
        delays = []
        scan_time = 0.0
        with mock.patch.object(
            ipa_redactor, "move_without_overwrite", side_effect=PermissionError("denied")
        ):
            for _ in range(5):
                self.process(
                    scan_time=scan_time,
                    max_processing_attempts=100,
                    retry_backoff_seconds=1000.0,
                )
                next_retry = self.retry_state[claimed][1]
                delays.append(next_retry - scan_time)
                scan_time = next_retry
        self.assertEqual(
            delays,
            [1000.0, 2000.0]
            + [ipa_redactor.MAX_RETRY_BACKOFF_SECONDS] * 3,
        )
        self.assertEqual(ipa_redactor.MAX_RETRY_BACKOFF_SECONDS, 3600.0)

    def test_archive_that_cannot_be_claimed_is_left_in_place_for_the_next_scan(self):
        original = self.create_bundle([("journal", "x\n")])
        with mock.patch.object(ipa_redactor, "claim_archive", return_value=None):
            self.assertEqual(self.process(), 0)
        self.assertTrue(original.exists())
        self.assertEqual(self.output.getvalue(), "")
        self.assertEqual(self.process(), 1)
        self.assertTrue(Path(str(original) + ".forwarded").exists())

    def test_dictionary_key_with_no_value_is_left_alone(self):
        for source in ("{'agent_token': ", "'agent_token':", "{'configdrive': \n"):
            with self.subTest(source=source):
                self.assertEqual(ipa_redactor.redact_line(source), source)

    def test_compressed_size_limit_accepts_exactly_the_limit_and_rejects_one_less(self):
        original = self.create_bundle([("journal", "x\n")])
        size = original.stat().st_size

        claimed = self.claim(original)
        self.assertTrue(self.run_claimed(claimed, max_archive_bytes=size))
        self.assertTrue(Path(str(original) + ".forwarded").exists())

        other = self.create_bundle(
            [("journal", "x\n")], context="dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        )
        claimed = self.claim(other)
        self.assertFalse(self.run_claimed(claimed, max_archive_bytes=size - 1))
        self.assert_failure_code("archive_too_large")

    def test_zero_backoff_retries_on_every_scan_until_the_limit(self):
        self.create_bundle([("journal", "stuck\n")])
        with mock.patch.object(
            ipa_redactor, "move_without_overwrite", side_effect=PermissionError("denied")
        ):
            for scan in range(6):
                self.process(
                    scan_time=scan,
                    max_processing_attempts=3,
                    retry_backoff_seconds=0.0,
                )
        self.assertEqual(self.count_starts(), 3)


ENVIRONMENT_VARIABLES = {
    # name: (expected parsed value, valid sample, invalid samples)
    "INTERVAL": (5.0, "5", ("0", "-1", "abc", "")),
    "STABILITY_SECONDS": (0.0, "0", ("-1", "abc")),
    "STATUS_INTERVAL_SECONDS": (0.0, "0", ("-1", "abc")),
    "MAX_ARCHIVE_BYTES": (10, "10", ("0", "-1", "1.5", "abc")),
    "MAX_MEMBER_BYTES": (10, "10", ("0", "-1", "1.5", "abc")),
    "MAX_LINE_BYTES": (10, "10", ("0", "-1", "1.5", "abc")),
    "MAX_TOTAL_ARCHIVE_BYTES": (10, "10", ("0", "-1", "1.5", "abc")),
    "MAX_TOTAL_OUTPUT_BYTES": (10, "10", ("0", "-1", "1.5", "abc")),
    "MAX_OUTPUT_LINES": (10, "10", ("0", "-1", "1.5", "abc")),
    "MAX_FORWARDED_BYTES": (10, "10", ("0", "-1", "1.5", "abc")),
    "MAX_ARCHIVE_MEMBERS": (10, "10", ("0", "-1", "1.5", "abc")),
    "FORWARDED_RETENTION_DAYS": (0, "0", ("-1", "1.5", "abc")),
    "FAILED_RETENTION_DAYS": (0, "0", ("-1", "1.5", "abc")),
    "CLEANUP_INTERVAL_SECONDS": (10, "10", ("0", "-1", "1.5", "abc")),
    "MAX_PROCESSING_ATTEMPTS": (10, "10", ("0", "-1", "1.5", "abc")),
    "RETRY_BACKOFF_SECONDS": (0.0, "0", ("-1", "abc")),
    "RETENTION_DRY_RUN": (False, "false", ("maybe", "2", "", "truthy")),
}


class ValidatorTests(unittest.TestCase):
    def assert_rejected(self, function, value, value_type, fragment):
        with self.assertRaises(argparse.ArgumentTypeError) as raised:
            function(value, value_type, "setting")
        self.assertIn("setting", str(raised.exception))
        self.assertIn(fragment, str(raised.exception))

    def test_positive_number_accepts_positive_values(self):
        self.assertEqual(ipa_redactor.positive_number("5", int, "x"), 5)
        self.assertEqual(ipa_redactor.positive_number("0.5", float, "x"), 0.5)

    def test_positive_number_rejects_zero_negative_and_non_numbers(self):
        for value, value_type, fragment in (
            ("0", int, "greater than zero"),
            ("-3", int, "greater than zero"),
            ("0.0", float, "greater than zero"),
            ("-0.5", float, "greater than zero"),
            ("abc", int, "must be a number"),
            ("", int, "must be a number"),
            ("1.5", int, "must be a number"),
            ("abc", float, "must be a number"),
        ):
            with self.subTest(value=value, value_type=value_type.__name__):
                self.assert_rejected(
                    ipa_redactor.positive_number, value, value_type, fragment
                )

    def test_non_negative_number_accepts_zero_and_positive_values(self):
        self.assertEqual(ipa_redactor.non_negative_number("0", int, "x"), 0)
        self.assertEqual(ipa_redactor.non_negative_number("7", int, "x"), 7)
        self.assertEqual(ipa_redactor.non_negative_number("0.25", float, "x"), 0.25)

    def test_non_negative_number_rejects_negative_and_non_numbers(self):
        for value, value_type, fragment in (
            ("-1", int, "zero or greater"),
            ("-0.1", float, "zero or greater"),
            ("abc", int, "must be a number"),
            ("1.5", int, "must be a number"),
        ):
            with self.subTest(value=value):
                self.assert_rejected(
                    ipa_redactor.non_negative_number, value, value_type, fragment
                )

    def test_boolean_value_accepts_documented_spellings(self):
        for value in ("1", "true", "TRUE", " yes ", "On", "ON"):
            with self.subTest(value=value):
                self.assertIs(ipa_redactor.boolean_value(value, "x"), True)
        for value in ("0", "false", "False", "No", "off", " OFF "):
            with self.subTest(value=value):
                self.assertIs(ipa_redactor.boolean_value(value, "x"), False)

    def test_boolean_value_rejects_anything_else(self):
        for value in ("maybe", "", "2", "truthy", "y", "t"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError) as raised:
                    ipa_redactor.boolean_value(value, "dry-run")
                self.assertIn("dry-run", str(raised.exception))

    def test_every_environment_variable_rejects_invalid_values(self):
        for name, (_expected, _valid, invalid_values) in ENVIRONMENT_VARIABLES.items():
            for bad in invalid_values:
                with self.subTest(name=name, value=bad):
                    environment = {"LOGS_DIR": "/logs", name: bad}
                    with mock.patch.dict("os.environ", environment, clear=True):
                        with self.assertRaises(argparse.ArgumentTypeError):
                            ipa_redactor.build_parser()

    def test_every_environment_variable_sets_the_expected_option(self):
        for name, (expected, valid, _invalid) in ENVIRONMENT_VARIABLES.items():
            with self.subTest(name=name, value=valid):
                environment = {"LOGS_DIR": "/logs", name: valid}
                with mock.patch.dict("os.environ", environment, clear=True):
                    args = ipa_redactor.build_parser().parse_args([])
                actual = getattr(args, name.lower())
                self.assertEqual(actual, expected)
                self.assertIs(type(actual), type(expected))

    def test_environment_variable_table_covers_every_variable_read_by_the_code(self):
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        read_by_code = set(re.findall(r'os\.environ\.get\(\s*"([A-Z_]+)"', source))
        self.assertEqual(read_by_code - {"LOGS_DIR"}, set(ENVIRONMENT_VARIABLES))

    def test_command_line_flags_override_the_environment(self):
        # Give every CLI setting a conflicting environment value so this
        # checks precedence for each option, rather than just CLI parsing.
        environment = {
            name: valid for name, (_expected, valid, _invalid) in ENVIRONMENT_VARIABLES.items()
        }
        environment["LOGS_DIR"] = "/from-env"
        argv = [
            "--logs-dir", "/from-cli",
            "--interval", "7",
            "--stability-seconds", "3",
            "--status-interval-seconds", "11",
            "--max-archive-bytes", "101",
            "--max-member-bytes", "102",
            "--max-line-bytes", "103",
            "--max-total-archive-bytes", "104",
            "--max-total-output-bytes", "105",
            "--max-output-lines", "106",
            "--max-forwarded-bytes", "107",
            "--max-archive-members", "108",
            "--forwarded-retention-days", "109",
            "--failed-retention-days", "110",
            "--cleanup-interval-seconds", "111",
            "--max-processing-attempts", "112",
            "--retry-backoff-seconds", "113",
            "--retention-dry-run",
            "--once",
        ]
        with mock.patch.dict("os.environ", environment, clear=True):
            args = ipa_redactor.build_parser().parse_args(argv)
        self.assertEqual(args.logs_dir, Path("/from-cli"))
        self.assertEqual(args.interval, 7.0)
        self.assertEqual(args.stability_seconds, 3.0)
        self.assertEqual(args.status_interval_seconds, 11.0)
        self.assertEqual(args.max_archive_bytes, 101)
        self.assertEqual(args.max_member_bytes, 102)
        self.assertEqual(args.max_line_bytes, 103)
        self.assertEqual(args.max_total_archive_bytes, 104)
        self.assertEqual(args.max_total_output_bytes, 105)
        self.assertEqual(args.max_output_lines, 106)
        self.assertEqual(args.max_forwarded_bytes, 107)
        self.assertEqual(args.max_archive_members, 108)
        self.assertEqual(args.forwarded_retention_days, 109)
        self.assertEqual(args.failed_retention_days, 110)
        self.assertEqual(args.cleanup_interval_seconds, 111)
        self.assertEqual(args.max_processing_attempts, 112)
        self.assertEqual(args.retry_backoff_seconds, 113.0)
        self.assertTrue(args.retention_dry_run)
        self.assertTrue(args.once)

    def test_no_retention_dry_run_flag_disables_dry_run(self):
        with mock.patch.dict("os.environ", {"LOGS_DIR": "/logs"}, clear=True):
            args = ipa_redactor.build_parser().parse_args(["--no-retention-dry-run"])
        self.assertFalse(args.retention_dry_run)
        self.assertFalse(args.once)

    def test_invalid_command_line_values_exit_with_usage_error(self):
        for argv in (
            ["--interval", "0"],
            ["--max-output-lines", "-1"],
            ["--max-archive-bytes", "abc"],
            ["--forwarded-retention-days", "-5"],
            ["--max-processing-attempts", "0"],
            ["--retry-backoff-seconds", "-1"],
            ["--unknown-flag"],
        ):
            with self.subTest(argv=argv):
                with mock.patch.dict("os.environ", {"LOGS_DIR": "/logs"}, clear=True):
                    parser = ipa_redactor.build_parser()
                    with mock.patch("sys.stderr", io.StringIO()):
                        with self.assertRaises(SystemExit) as raised:
                            parser.parse_args(argv)
                self.assertEqual(raised.exception.code, 2)


class MainTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(mock.patch.dict("os.environ", isolated_environment(), clear=True))
        self.temp_dir = tempfile.TemporaryDirectory()
        self.logs_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_main(self, argv):
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", output), mock.patch("sys.stderr", errors):
            code = ipa_redactor.main(argv)
        return code, output.getvalue(), errors.getvalue()

    def create_bundle(self, members, name=None):
        name = name or "{}_node1_cleaning_2026-09-14-04-12-03.tar.gz".format(NODE_UUID)
        path = self.logs_dir / name
        with tarfile.open(path, "w:gz") as archive:
            for member_name, content in members:
                add_bytes(archive, member_name, content)
        return path

    def test_missing_logs_dir_fails_without_leaking_the_path(self):
        missing = self.logs_dir / "does-not-exist"
        code, output, errors = self.run_main(["--logs-dir", str(missing), "--once"])
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        records = structured_records(errors)
        self.assertEqual(
            records,
            [{"event": "startup_failed", "error_code": "invalid_logs_dir"}],
        )
        self.assertNotIn("does-not-exist", errors)

    def test_logs_dir_that_is_a_file_fails(self):
        not_a_directory = self.logs_dir / "file.txt"
        not_a_directory.write_text("x")
        code, output, errors = self.run_main(
            ["--logs-dir", str(not_a_directory), "--once"]
        )
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertIn("invalid_logs_dir", errors)

    def test_startup_record_reports_the_watched_directory_and_inventory(self):
        code, output, _errors = self.run_main(
            ["--logs-dir", str(self.logs_dir), "--stability-seconds", "0", "--once"]
        )
        self.assertEqual(code, 0)
        record = structured_records(output)[0]
        self.assertEqual(record["logs_dir"], str(self.logs_dir))

    def test_once_mode_processes_redacts_and_marks_a_bundle(self):
        original = self.create_bundle([("journal", "agent_token=SYNTH-main\nok\n")])
        code, output, errors = self.run_main(
            ["--logs-dir", str(self.logs_dir), "--stability-seconds", "0", "--once"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(errors, "")
        self.assertNotIn("SYNTH-main", output)
        self.assertIn("[journal] agent_token=REDACTED", output)
        self.assertEqual(
            [r["event"] for r in structured_records(output)],
            ["redactor_started", "archive_start", "archive_complete"],
        )
        self.assertTrue(Path(str(original) + ".forwarded").exists())
        self.assertFalse(original.exists())

    def test_once_mode_keeps_scanning_until_the_stability_window_passes(self):
        original = self.create_bundle([("journal", "waits\n")])
        ticks = itertools.count(0, 30)
        sleeps = []
        with (
            mock.patch.object(ipa_redactor.time, "monotonic", lambda: next(ticks)),
            mock.patch.object(ipa_redactor.time, "sleep", sleeps.append),
        ):
            code, output, _errors = self.run_main(
                [
                    "--logs-dir", str(self.logs_dir),
                    "--stability-seconds", "60",
                    "--interval", "17",
                    "--once",
                ]
            )
        self.assertEqual(code, 0)
        self.assertGreaterEqual(len(sleeps), 1)
        self.assertEqual(set(sleeps), {17.0})
        self.assertIn("archive_complete", output)
        self.assertTrue(Path(str(original) + ".forwarded").exists())

    def test_expired_archives_are_removed_only_when_dry_run_is_disabled(self):
        expired = self.logs_dir / "old.tar.gz.forwarded"
        expired.write_bytes(b"x")
        ten_days_ago = time.time() - 10 * 24 * 3600
        os.utime(expired, (ten_days_ago, ten_days_ago))
        base = [
            "--logs-dir", str(self.logs_dir),
            "--stability-seconds", "0",
            "--forwarded-retention-days", "1",
            "--once",
        ]

        _code, output, _errors = self.run_main(base)
        self.assertTrue(expired.exists())
        self.assertIn("retention dry-run: would remove expired forwarded", output)

        _code, output, _errors = self.run_main(base + ["--no-retention-dry-run"])
        self.assertFalse(expired.exists())
        self.assertIn("removed expired forwarded archive", output)

    def test_settings_are_passed_to_processing_and_cleanup_in_the_right_order(self):
        argv = [
            "--logs-dir", str(self.logs_dir),
            "--stability-seconds", "3",
            "--max-archive-bytes", "101",
            "--max-member-bytes", "102",
            "--max-line-bytes", "103",
            "--max-total-archive-bytes", "104",
            "--max-total-output-bytes", "105",
            "--max-output-lines", "106",
            "--max-forwarded-bytes", "107",
            "--max-archive-members", "108",
            "--forwarded-retention-days", "109",
            "--failed-retention-days", "110",
            "--max-processing-attempts", "112",
            "--retry-backoff-seconds", "113",
            "--no-retention-dry-run",
            "--once",
        ]
        output, errors = io.StringIO(), io.StringIO()
        with (
            mock.patch("sys.stdout", output),
            mock.patch("sys.stderr", errors),
            mock.patch.object(ipa_redactor, "process_available", return_value=0) as process,
            mock.patch.object(ipa_redactor, "cleanup_expired_archives", return_value=0) as cleanup,
        ):
            self.assertEqual(ipa_redactor.main(argv), 0)

        positional = process.call_args.args
        self.assertEqual(positional[0], self.logs_dir)
        self.assertIs(positional[1], output)
        self.assertIs(positional[2], errors)
        self.assertEqual(
            positional[3:11],
            (
                108,  # max_archive_members
                101,  # max_archive_bytes
                104,  # max_total_archive_bytes
                102,  # max_member_bytes
                103,  # max_line_bytes
                105,  # max_total_output_bytes
                106,  # max_output_lines
                107,  # max_forwarded_bytes
            ),
        )
        self.assertIsInstance(positional[11], dict)
        self.assertEqual(positional[12], 3.0)
        self.assertIsInstance(process.call_args.kwargs["retry_state"], dict)
        self.assertEqual(process.call_args.kwargs["max_processing_attempts"], 112)
        self.assertEqual(process.call_args.kwargs["retry_backoff_seconds"], 113.0)

        self.assertEqual(
            cleanup.call_args.args,
            (self.logs_dir, output, errors, 109, 110, False),
        )

    def test_cleanup_runs_on_its_own_interval(self):
        ticks = iter([0, 10, 50, 120])
        sleep_calls = []

        def interrupt_on_third_sleep(seconds):
            sleep_calls.append(seconds)
            if len(sleep_calls) == 3:
                raise KeyboardInterrupt

        with (
            mock.patch.object(ipa_redactor, "process_available", return_value=0),
            mock.patch.object(ipa_redactor, "cleanup_expired_archives", return_value=0) as cleanup,
            mock.patch.object(ipa_redactor.time, "monotonic", lambda: next(ticks)),
            mock.patch.object(ipa_redactor.time, "sleep", interrupt_on_third_sleep),
        ):
            code, _output, _errors = self.run_main(
                [
                    "--logs-dir", str(self.logs_dir),
                    "--cleanup-interval-seconds", "100",
                    "--status-interval-seconds", "0",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(cleanup.call_count, 2)

    def test_status_heartbeat_can_be_disabled(self):
        with (
            mock.patch.object(ipa_redactor, "process_available", return_value=0),
            mock.patch.object(ipa_redactor, "cleanup_expired_archives", return_value=0),
            mock.patch.object(ipa_redactor.time, "sleep", side_effect=KeyboardInterrupt),
        ):
            _code, output, _errors = self.run_main(
                ["--logs-dir", str(self.logs_dir), "--status-interval-seconds", "0"]
            )
        self.assertEqual(
            [r["event"] for r in structured_records(output)], ["redactor_started"]
        )

    def test_keyboard_interrupt_exits_cleanly(self):
        with (
            mock.patch.object(ipa_redactor, "process_available", side_effect=KeyboardInterrupt),
        ):
            code, _output, errors = self.run_main(["--logs-dir", str(self.logs_dir)])
        self.assertEqual(code, 0)
        self.assertEqual(errors, "")

    def test_broken_stdout_exits_with_failure_and_closes_stdout(self):
        for close_raises in (False, True):
            with self.subTest(close_raises=close_raises):

                class FakeStdout(io.StringIO):
                    closed_by_main = False

                    def close(self):
                        FakeStdout.closed_by_main = True
                        if close_raises:
                            raise BrokenPipeError()
                        super().close()

                fake = FakeStdout()
                with (
                    mock.patch("sys.stdout", fake),
                    mock.patch("sys.stderr", io.StringIO()),
                    mock.patch.object(
                        ipa_redactor, "process_available", side_effect=BrokenPipeError
                    ),
                ):
                    code = ipa_redactor.main(["--logs-dir", str(self.logs_dir)])
                self.assertEqual(code, 1)
                self.assertTrue(FakeStdout.closed_by_main)

    def test_stuck_archive_limit_is_honoured_through_the_command_line(self):
        self.create_bundle([("journal", "stuck\n")])
        with mock.patch.object(
            ipa_redactor, "move_without_overwrite", side_effect=PermissionError("denied")
        ):
            code, output, errors = self.run_main(
                [
                    "--logs-dir", str(self.logs_dir),
                    "--stability-seconds", "0",
                    "--max-processing-attempts", "1",
                    "--once",
                ]
            )
        self.assertEqual(code, 0)
        self.assertIn("archive_retry_limit_reached", errors)
        self.assertEqual(output.count('"event":"archive_start"'), 1)


class ScriptEntryPointTests(unittest.TestCase):
    """Run the script the way the container does: as a separate process."""

    def run_script(self, *args, extra_env=None):
        environment = isolated_environment()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment.update(extra_env or {})
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), *args],
            capture_output=True,
            text=True,
            env=environment,
            timeout=60,
        )

    def test_help_lists_the_documented_flags(self):
        result = self.run_script("--help")
        self.assertEqual(result.returncode, 0)
        for flag in ("--logs-dir", "--once", "--max-processing-attempts", "--no-retention-dry-run"):
            self.assertIn(flag, result.stdout)

    def test_missing_logs_dir_setting_is_a_usage_error(self):
        result = self.run_script("--once")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--logs-dir", result.stderr)

    def test_nonexistent_directory_exits_with_code_two(self):
        result = self.run_script("--logs-dir", "/nonexistent-ipa-logs-dir", "--once")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid_logs_dir", result.stderr)

    def test_process_forwards_and_redacts_a_bundle_end_to_end(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            name = "{}_node1_{}_2026-09-14-04-12-03.tar.gz".format(
                NODE_UUID, INSTANCE_UUID
            )
            bundle = Path(temp_dir) / name
            with tarfile.open(bundle, "w:gz") as archive:
                add_bytes(archive, "journal", "rootpwd=SYNTH-e2e ok\n")
                add_bytes(archive, "dmesg", "Authorization: Bearer SYNTH-e2e\n")
                add_bytes(archive, "ignored", "SYNTH-e2e must not appear\n")
            result = self.run_script(
                "--once", "--stability-seconds", "0", extra_env={"LOGS_DIR": temp_dir}
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertNotIn("SYNTH-e2e", result.stdout)
            self.assertIn("rootpwd=REDACTED ok", result.stdout)
            self.assertIn("Authorization: REDACTED", result.stdout)
            self.assertIn('"event":"archive_complete"', result.stdout)
            self.assertTrue(Path(str(bundle) + ".forwarded").exists())


class EventFormatTests(unittest.TestCase):
    def emit(self, *args, **kwargs):
        output = io.StringIO()
        ipa_redactor.emit_lifecycle_event(output, *args, **kwargs)
        return output.getvalue()

    def test_archive_start_has_the_documented_exact_format(self):
        self.assertEqual(
            self.emit("archive_start", "a1", "bundle.tar.gz", "t1"),
            '[ipa-log-redactor] {"event":"archive_start","archive_id":"a1",'
            '"attempt_id":"t1","status":"processing","archive_name":"bundle.tar.gz"}\n',
        )

    def test_complete_and_failed_events_omit_the_archive_name(self):
        complete = self.emit("archive_complete", "a1", "bundle.tar.gz", "t1")
        self.assertEqual(
            complete,
            '[ipa-log-redactor] {"event":"archive_complete","archive_id":"a1",'
            '"attempt_id":"t1","status":"processed"}\n',
        )
        failed = self.emit(
            "archive_failed", "a1", "bundle.tar.gz", "t1", "missing_journal"
        )
        self.assertEqual(
            failed,
            '[ipa-log-redactor] {"event":"archive_failed","archive_id":"a1",'
            '"attempt_id":"t1","status":"failed","error_code":"missing_journal"}\n',
        )

    def test_lifecycle_misuse_is_rejected(self):
        with self.assertRaises(ValueError):
            self.emit("archive_failed", "a1", "n", "t1")
        with self.assertRaises(ValueError):
            self.emit("archive_failed", "a1", "n", "t1", "free text error")
        with self.assertRaises(ValueError):
            self.emit("archive_complete", "a1", "n", "t1", "missing_journal")
        with self.assertRaises(ValueError):
            self.emit("archive_start", "a1", "n", "t1", "missing_journal")
        with self.assertRaises(KeyError):
            self.emit("archive_unknown", "a1", "n", "t1")

    def test_every_controlled_error_code_can_be_reported(self):
        self.assertGreaterEqual(len(ipa_redactor.FAILURE_ERROR_CODES), 10)
        for code in sorted(ipa_redactor.FAILURE_ERROR_CODES):
            with self.subTest(code=code):
                self.assertRegex(code, r"^[a-z]+(_[a-z]+)*$")
                record = json.loads(
                    self.emit("archive_failed", "a", "n", "t", code).split(" ", 1)[1]
                )
                self.assertEqual(record["error_code"], code)

    def test_bundle_errors_only_accept_controlled_codes(self):
        with self.assertRaises(ValueError):
            ipa_redactor.BundleError("not_a_real_code", "message")
        error = ipa_redactor.BundleError("missing_journal", "message")
        self.assertEqual(error.error_code, "missing_journal")
        collision = ipa_redactor.OutcomeCollisionError("message")
        self.assertIsInstance(collision, ipa_redactor.BundleError)
        self.assertEqual(collision.error_code, "outcome_collision")

    def test_every_error_code_used_in_the_source_is_controlled(self):
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
        used = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "BundleError"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                used.add(node.args[0].value)
        self.assertGreaterEqual(len(used), 10)
        self.assertLessEqual(used, ipa_redactor.FAILURE_ERROR_CODES)

    def test_status_and_operational_events_are_compact_tagged_json(self):
        output = io.StringIO()
        ipa_redactor.emit_status_event(output, "redactor_status", status="watching", n=1)
        self.assertEqual(
            output.getvalue(),
            '[ipa-log-redactor] {"event":"redactor_status","status":"watching","n":1}\n',
        )
        output = io.StringIO()
        ipa_redactor.emit_operational_event(output, "some_event", "filesystem_error", id="x")
        self.assertEqual(
            output.getvalue(),
            '[ipa-log-redactor] {"event":"some_event","error_code":"filesystem_error","id":"x"}\n',
        )

    def test_events_are_flushed_immediately(self):
        for emitter, args in (
            (ipa_redactor.emit_status_event, ("e",)),
            (ipa_redactor.emit_operational_event, ("e", "filesystem_error")),
            (ipa_redactor.emit_lifecycle_event, ("archive_complete", "a", "n", "t")),
        ):
            with self.subTest(emitter=emitter.__name__):
                output = mock.Mock(spec=io.StringIO)
                emitter(output, *args)
                self.assertEqual(
                    [call[0] for call in output.mock_calls], ["write", "flush"]
                )

    def test_inventory_counts_each_outcome_and_ignores_other_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            for name in (
                "a.tar.gz",
                "b.tar.gz",
                "c.tar.gz.processing",
                "d.tar.gz.forwarded",
                "e.tar.gz.forwarded",
                "f.tar.gz.forwarded",
                "g.tar.gz.failed",
                "h.tar.gz.failed.20260925T120000Z",
                "notes.txt",
                "x.zip",
            ):
                (directory / name).write_bytes(b"x")
            self.assertEqual(
                ipa_redactor.archive_inventory(directory),
                {
                    "pending_archives": 2,
                    "processing_archives": 1,
                    "forwarded_archives": 3,
                    "failed_archives": 2,
                },
            )


class BundleNameTests2(unittest.TestCase):
    def name(self, node="node1", context="cleaning", timestamp="2026-09-14-04-12-03", suffix=".tar.gz"):
        return "{}_{}_{}_{}{}".format(NODE_UUID, node, context, timestamp, suffix)

    def test_name_is_parsed_with_and_without_the_processing_suffix(self):
        for suffix in (".tar.gz", ".tar.gz.processing"):
            with self.subTest(suffix=suffix):
                self.assertEqual(
                    ipa_redactor.parse_bundle_name(Path(self.name(suffix=suffix))),
                    ("node1", "cleaning"),
                )

    def test_instance_uuid_context_is_returned(self):
        self.assertEqual(
            ipa_redactor.parse_bundle_name(Path(self.name(context=INSTANCE_UUID))),
            ("node1", INSTANCE_UUID),
        )

    def test_impossible_timestamps_are_rejected(self):
        for timestamp in (
            "2026-13-09-07-04-12",
            "2026-00-09-07-04-12",
            "2026-09-31-07-04-12",
            "2026-02-30-07-04-12",
            "2026-09-09-25-04-12",
            "2026-09-09-07-61-12",
        ):
            with self.subTest(timestamp=timestamp):
                with self.assertRaises(ipa_redactor.BundleError) as raised:
                    ipa_redactor.parse_bundle_name(Path(self.name(timestamp=timestamp)))
                self.assertEqual(raised.exception.error_code, "invalid_filename")

    def test_malformed_names_are_rejected(self):
        bad_names = [
            "bundle.tar.gz",
            "not-a-uuid_node1_cleaning_2026-09-14-04-12-03.tar.gz",
            self.name(suffix=".tar"),
            self.name(suffix=".TAR.GZ"),
            self.name(suffix=".tar.gz.forwarded"),
            self.name(suffix=".tar.gz.bak"),
            self.name(context="Cleaning"),
            self.name(context="deploying"),
            self.name(context="f685f191-edac-4786-8ee5-b772b0b21d0"),
            self.name(timestamp="2026-9-14-04-12-03"),
            self.name(timestamp="20260914041203"),
            self.name(node=""),
            self.name(node="-leading-hyphen"),
            self.name(node=".leading-dot"),
            self.name(node="_leading_underscore"),
            self.name(node="has space"),
            self.name(node="tab\there"),
            self.name(node="new\nline"),
            self.name(node="semi;colon"),
            self.name(node="back`tick"),
            self.name(node="dollar$sign"),
            self.name(node="unicode-é"),
            "x_" + self.name(),
            self.name() + "x",
        ]
        for name in bad_names:
            with self.subTest(name=name):
                with self.assertRaises(ipa_redactor.BundleError) as raised:
                    ipa_redactor.parse_bundle_name(Path(name))
                self.assertEqual(raised.exception.error_code, "invalid_filename")

    def test_hostname_safe_node_names_are_accepted(self):
        for node in ("n", "1362737-compute2", "a.b.c", "x_y_z", "Node-01", "9"):
            with self.subTest(node=node):
                self.assertEqual(
                    ipa_redactor.parse_bundle_name(Path(self.name(node=node)))[0], node
                )

    def test_archive_id_is_stable_short_and_independent_of_the_processing_suffix(self):
        plain = Path(self.name())
        claimed = Path(self.name(suffix=".tar.gz.processing"))
        expected = __import__("hashlib").sha256(plain.name.encode()).hexdigest()[:16]
        self.assertEqual(ipa_redactor.archive_id_for(plain), expected)
        self.assertEqual(ipa_redactor.archive_id_for(claimed), expected)
        self.assertEqual(len(expected), ipa_redactor.ARCHIVE_ID_HEX_LENGTH)
        self.assertNotEqual(
            ipa_redactor.archive_id_for(plain),
            ipa_redactor.archive_id_for(Path(self.name(node="node2"))),
        )

    def test_original_name_removes_only_a_trailing_processing_suffix(self):
        self.assertEqual(
            ipa_redactor.original_archive_name(Path("a.tar.gz.processing")), "a.tar.gz"
        )
        self.assertEqual(ipa_redactor.original_archive_name(Path("a.tar.gz")), "a.tar.gz")
        self.assertEqual(
            ipa_redactor.original_archive_name(Path("a.processing.tar.gz")),
            "a.processing.tar.gz",
        )


class FilesystemHelperTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp_dir.name)
        self.addCleanup(self.temp_dir.cleanup)
        self.errors = io.StringIO()

    def make(self, name, content=b"x"):
        path = self.directory / name
        path.write_bytes(content)
        return path

    def test_path_entry_exists_includes_dangling_symlinks(self):
        regular = self.make("regular")
        dangling = self.directory / "dangling"
        dangling.symlink_to(self.directory / "nowhere")
        self.assertTrue(ipa_redactor.path_entry_exists(regular))
        self.assertTrue(ipa_redactor.path_entry_exists(dangling))
        self.assertFalse(ipa_redactor.path_entry_exists(self.directory / "missing"))

    def test_outcome_path_handles_claimed_and_unclaimed_names(self):
        self.assertEqual(
            ipa_redactor.outcome_path(Path("/d/a.tar.gz.processing"), "forwarded"),
            Path("/d/a.tar.gz.forwarded"),
        )
        self.assertEqual(
            ipa_redactor.outcome_path(Path("/d/a.tar.gz"), "failed"),
            Path("/d/a.tar.gz.failed"),
        )

    def test_move_without_overwrite_moves_the_file(self):
        source = self.make("a.tar.gz.processing", b"payload")
        destination = self.directory / "a.tar.gz.forwarded"
        ipa_redactor.move_without_overwrite(source, destination)
        self.assertFalse(source.exists())
        self.assertEqual(destination.read_bytes(), b"payload")

    def test_move_without_overwrite_never_replaces_existing_entries(self):
        for label, prepare in (
            ("regular file", lambda d: d.write_bytes(b"existing")),
            ("dangling symlink", lambda d: d.symlink_to(self.directory / "nowhere")),
            ("directory", lambda d: d.mkdir()),
        ):
            with self.subTest(existing=label):
                source = self.make("src-{}".format(label.replace(" ", "-")), b"new")
                destination = self.directory / "dest-{}".format(label.replace(" ", "-"))
                prepare(destination)
                with self.assertRaises(ipa_redactor.OutcomeCollisionError):
                    ipa_redactor.move_without_overwrite(source, destination)
                self.assertEqual(source.read_bytes(), b"new")
                if label == "regular file":
                    self.assertEqual(destination.read_bytes(), b"existing")

    def test_symlink_source_is_not_followed_when_moved(self):
        target = self.make("target", b"target-content")
        link = self.directory / "link.tar.gz.processing"
        link.symlink_to(target)
        destination = self.directory / "link.tar.gz.forwarded"
        ipa_redactor.move_without_overwrite(link, destination)
        self.assertTrue(target.exists())
        self.assertTrue(destination.is_symlink())

    def test_mark_outcome_sets_the_requested_modification_time(self):
        claimed = self.make("a.tar.gz.processing")
        os.utime(claimed, (1_000_000_000, 1_000_000_000))
        destination = ipa_redactor.mark_outcome(claimed, "failed", outcome_time=1_700_000_000)
        self.assertEqual(destination, self.directory / "a.tar.gz.failed")
        self.assertEqual(int(destination.stat().st_mtime), 1_700_000_000)

    def test_mark_outcome_defaults_to_the_current_time(self):
        claimed = self.make("a.tar.gz.processing")
        os.utime(claimed, (1_000_000_000, 1_000_000_000))
        before = time.time()
        destination = ipa_redactor.mark_outcome(claimed, "forwarded")
        self.assertGreaterEqual(destination.stat().st_mtime, int(before) - 1)

    def test_mark_outcome_collision_preserves_both_files_contents(self):
        claimed = self.make("a.tar.gz.processing", b"claimed")
        existing = self.make("a.tar.gz.forwarded", b"existing")
        with self.assertRaises(ipa_redactor.OutcomeCollisionError):
            ipa_redactor.mark_outcome(claimed, "forwarded")
        self.assertEqual(claimed.read_bytes(), b"claimed")
        self.assertEqual(existing.read_bytes(), b"existing")

    def test_quarantine_uses_a_utc_timestamp_and_reports_the_move(self):
        claimed = self.make("a.tar.gz.processing")
        destination = ipa_redactor.quarantine_archive(
            claimed, self.errors, quarantine_time=1_790_000_000
        )
        self.assertEqual(destination.name, "a.tar.gz.failed.20260921T141320Z")
        self.assertFalse(claimed.exists())
        self.assertEqual(int(destination.stat().st_mtime), 1_790_000_000)
        self.assertRegex(destination.name, ipa_redactor.QUARANTINED_FAILED_NAME_RE)
        records = structured_records(self.errors.getvalue())
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["event"], "archive_quarantined")
        self.assertEqual(records[0]["error_code"], "outcome_collision")
        self.assertEqual(records[0]["archive_name"], "a.tar.gz")
        self.assertEqual(records[0]["quarantine_name"], destination.name)
        self.assertEqual(
            records[0]["archive_id"], ipa_redactor.archive_id_for(Path("a.tar.gz"))
        )

    def test_repeated_quarantines_get_unique_numbered_names(self):
        names = []
        for _ in range(4):
            claimed = self.make("a.tar.gz.processing")
            names.append(
                ipa_redactor.quarantine_archive(
                    claimed, self.errors, quarantine_time=1_790_000_000
                ).name
            )
        self.assertEqual(
            names,
            [
                "a.tar.gz.failed.20260921T141320Z",
                "a.tar.gz.failed.20260921T141320Z.1",
                "a.tar.gz.failed.20260921T141320Z.2",
                "a.tar.gz.failed.20260921T141320Z.3",
            ],
        )
        for name in names:
            self.assertRegex(name, ipa_redactor.QUARANTINED_FAILED_NAME_RE)

    def test_quarantined_archives_are_picked_up_by_failed_retention(self):
        claimed = self.make("a.tar.gz.processing")
        destination = ipa_redactor.quarantine_archive(
            claimed, self.errors, quarantine_time=1_000_000_000
        )
        self.assertIn(destination, list(ipa_redactor.outcome_archives(self.directory, "failed")))
        removed = ipa_redactor.cleanup_expired_archives(
            self.directory, io.StringIO(), self.errors, 90, 90, dry_run=False, now=2_000_000_000
        )
        self.assertEqual(removed, 1)
        self.assertFalse(destination.exists())

    def test_outcome_archives_returns_only_exact_and_valid_quarantine_names(self):
        wanted = [
            self.make("a.tar.gz.failed"),
            self.make("b.tar.gz.failed.20260921T143320Z"),
            self.make("c.tar.gz.failed.20260921T143320Z.7"),
        ]
        for unwanted in (
            "d.tar.gz.failed.bak",
            "e.tar.gz.failed.20260921T143320",
            "f.tar.gz.forwarded",
            "g.failed",
        ):
            self.make(unwanted)
        self.assertEqual(
            list(ipa_redactor.outcome_archives(self.directory, "failed")), sorted(wanted)
        )
        self.assertEqual(
            [p.name for p in ipa_redactor.outcome_archives(self.directory, "forwarded")],
            ["f.tar.gz.forwarded"],
        )


class MemberSelectionTests(unittest.TestCase):
    LIMITS = dict(
        max_archive_members=100,
        max_total_archive_bytes=1000,
        max_member_bytes=500,
        max_total_output_bytes=800,
    )

    def member(self, name, size=1, member_type=tarfile.REGTYPE):
        info = tarfile.TarInfo(name)
        info.size = size
        info.type = member_type
        return info

    def select(self, members, **overrides):
        limits = dict(self.LIMITS)
        limits.update(overrides)
        return ipa_redactor.selected_members(members, **limits)

    def assert_code(self, members, code, **overrides):
        with self.assertRaises(ipa_redactor.BundleError) as raised:
            self.select(members, **overrides)
        self.assertEqual(raised.exception.error_code, code)

    def test_selects_only_allow_listed_names(self):
        selected = self.select(
            [self.member("journal"), self.member("extra"), self.member("dmesg")]
        )
        self.assertEqual(sorted(selected), ["dmesg", "journal"])

    def test_journal_is_required(self):
        self.assert_code([self.member("dmesg")], "missing_journal")
        self.assert_code([], "missing_journal")

    def test_negative_member_size_is_invalid(self):
        self.assert_code([self.member("journal", size=-1)], "invalid_archive")
        self.assert_code(
            [self.member("journal"), self.member("ignored", size=-1)],
            "invalid_archive",
        )

    def test_member_count_limit_boundary(self):
        members = [self.member("journal")] + [self.member("x%d" % i) for i in range(2)]
        self.assertIn("journal", self.select(members, max_archive_members=3))
        self.assert_code(members, "too_many_members", max_archive_members=2)

    def test_total_archive_size_boundary_includes_ignored_members(self):
        members = [self.member("journal", 400), self.member("ignored", 600)]
        self.assertIn("journal", self.select(members, max_total_archive_bytes=1000))
        self.assert_code(members, "total_archive_too_large", max_total_archive_bytes=999)

    def test_single_member_size_boundary(self):
        self.assertIn("journal", self.select([self.member("journal", 500)]))
        self.assert_code([self.member("journal", 501)], "member_too_large")

    def test_ignored_members_may_exceed_the_per_member_limit(self):
        selected = self.select(
            [self.member("journal", 10), self.member("huge-ignored", 900)],
            max_total_archive_bytes=2000,
        )
        self.assertEqual(list(selected), ["journal"])

    def test_total_selected_size_boundary_excludes_ignored_members(self):
        members = [
            self.member("journal", 400),
            self.member("dmesg", 400),
            self.member("ignored", 150),
        ]
        self.assertEqual(
            sorted(self.select(members, max_total_archive_bytes=2000)),
            ["dmesg", "journal"],
        )
        self.assert_code(
            members,
            "total_output_too_large",
            max_total_archive_bytes=2000,
            max_total_output_bytes=799,
        )

    def test_duplicate_selected_member_is_rejected(self):
        self.assert_code([self.member("journal"), self.member("journal")], "duplicate_member")

    def test_duplicate_ignored_members_are_tolerated(self):
        selected = self.select(
            [self.member("journal"), self.member("other"), self.member("other")]
        )
        self.assertEqual(list(selected), ["journal"])

    def test_selected_members_must_be_regular_files(self):
        for label, member_type in (
            ("directory", tarfile.DIRTYPE),
            ("symlink", tarfile.SYMTYPE),
            ("hard link", tarfile.LNKTYPE),
            ("character device", tarfile.CHRTYPE),
            ("block device", tarfile.BLKTYPE),
            ("fifo", tarfile.FIFOTYPE),
        ):
            with self.subTest(member_type=label):
                self.assert_code(
                    [self.member("journal", 0, member_type)], "unsafe_member_type"
                )

    def test_non_regular_ignored_members_do_not_matter(self):
        selected = self.select(
            [self.member("journal"), self.member("link", 0, tarfile.SYMTYPE)]
        )
        self.assertEqual(list(selected), ["journal"])

    def test_optional_member_with_unsafe_type_is_rejected(self):
        self.assert_code(
            [self.member("journal"), self.member("dmesg", 0, tarfile.SYMTYPE)],
            "unsafe_member_type",
        )


class StreamingLimitTests(unittest.TestCase):
    def test_unreadable_member_is_reported(self):
        class NoData:
            def extractfile(self, member):
                return None

        with self.assertRaises(ipa_redactor.BundleError) as raised:
            ipa_redactor.stream_member(
                NoData(),
                tarfile.TarInfo("journal"),
                "[node]",
                "abc",
                io.StringIO(),
                1024,
                ipa_redactor.OutputBudget(10, 1000),
            )
        self.assertEqual(raised.exception.error_code, "unreadable_member")

    def test_output_budget_line_limit_boundary(self):
        budget = ipa_redactor.OutputBudget(max_lines=2, max_bytes=1000)
        output = io.StringIO()
        budget.write(output, "a\n")
        budget.write(output, "b\n")
        with self.assertRaises(ipa_redactor.BundleError) as raised:
            budget.write(output, "c\n")
        self.assertEqual(raised.exception.error_code, "too_many_output_lines")
        self.assertEqual(output.getvalue(), "a\nb\n")
        self.assertEqual(budget.lines, 2)

    def test_output_budget_byte_limit_boundary_counts_utf8_bytes(self):
        output = io.StringIO()
        budget = ipa_redactor.OutputBudget(max_lines=10, max_bytes=6)
        budget.write(output, "é\n")  # 3 bytes
        budget.write(output, "é\n")  # 3 bytes, exactly at the limit
        self.assertEqual(budget.bytes, 6)
        with self.assertRaises(ipa_redactor.BundleError) as raised:
            budget.write(output, "\n")
        self.assertEqual(raised.exception.error_code, "forwarded_output_too_large")
        self.assertEqual(output.getvalue(), "é\né\n")

    def test_rejected_record_is_not_partially_written(self):
        budget = ipa_redactor.OutputBudget(max_lines=10, max_bytes=5)
        output = io.StringIO()
        with self.assertRaises(ipa_redactor.BundleError):
            budget.write(output, "123456\n")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual((budget.lines, budget.bytes), (0, 0))


SECRET_CORPUS = (
    # (input line, expected redacted line). Values are synthetic and every
    # SYNTH marker must disappear. Shapes follow captured IPA logs.
    ("agent_token=SYNTH1 heartbeat ok", "agent_token=REDACTED heartbeat ok"),
    ("AGENT_TOKEN = 'SYNTH two' x", "AGENT_TOKEN=REDACTED x"),
    ("ipa-agent-token: SYNTH3 next=1", "ipa-agent-token: REDACTED next=1"),
    (
        "{'agent_secret_token': 'SYNTH4', 'safe': 1}",
        "{'agent_secret_token': 'REDACTED', 'safe': 1}",
    ),
    ('{"agent_token": "SYNTH5", "safe": 1}', '{"agent_token": \'REDACTED\', "safe": 1}'),
    (
        "kernel_append_params = nomodeset rootpwd=SYNTH6 sshkey=SYNTH7",
        "kernel_append_params=REDACTED",
    ),
    (
        "Command line: a=1 rootpwd=SYNTH8/x+y=z ipa-api-url=https://ironic.example.invalid b=2",
        "Command line: a=1 rootpwd=REDACTED ipa-api-url=https://ironic.example.invalid b=2",
    ),
    (
        "GET /v1/commands/?wait=true&agent_token=SYNTH9 - 200 (0.37ms)",
        "GET /v1/commands/?wait=true&agent_token=REDACTED - 200 (0.37ms)",
    ),
    ("Authorization: Bearer SYNTH10", "Authorization: REDACTED"),
    ("authorization=Bearer SYNTH11 retries=3", "authorization=REDACTED retries=3"),
    (
        "{'X-Auth-Token': 'SYNTH12', 'Accept': 'json'}",
        "{'X-Auth-Token': 'REDACTED', 'Accept': 'json'}",
    ),
    ("fetch ftp://user:SYNTH13@host/f now", "fetch ftp://REDACTED@host/f now"),
    (
        "http://swift.example.invalid/v1/AUTH_x/c/o?temp_url_sig=SYNTH14&temp_url_expires=1",
        "http://swift.example.invalid/v1/AUTH_x/c/o?temp_url_sig=REDACTED&temp_url_expires=1",
    ),
    (
        "https://b.example.invalid/o?X-Amz-Credential=SYNTH15&X-Amz-Expires=3600&X-Amz-Signature=SYNTH16",
        "https://b.example.invalid/o?X-Amz-Credential=REDACTED&X-Amz-Expires=3600&X-Amz-Signature=REDACTED",
    ),
    (
        "key ssh-rsa AAAAB3NzaC1yc2EAAAADAQABSYNTH17 user@host",
        "key SSH_PUBLIC_KEY_REDACTED",
    ),
    (
        "{'configdrive': {'user_data': 'SYNTH18', 'x': [1, 2]}, 'agent_token_required': True}",
        "{'configdrive': 'REDACTED', 'agent_token_required': True}",
    ),
    (
        "{'driver_info': {'redfish_username': 'SYNTH19', 'redfish_password': 'SYNTH20', "
        "'redfish_address': 'https://192.0.2.1'}}",
        "{'driver_info': {'redfish_username': 'REDACTED', 'redfish_password': 'REDACTED', "
        "'redfish_address': 'https://192.0.2.1'}}",
    ),
    ("redfish_password='a\\'SYNTH21b' next=1", "redfish_password=REDACTED next=1"),
    ('agent_token="SYNTH22 unterminated', "agent_token=REDACTED"),
    (
        "{'ssh_authorized_keys': ['ssh-rsa AAAA SYNTH23', 'x'], 'k': 1}",
        "{'ssh_authorized_keys': 'REDACTED', 'k': 1}",
    ),
    (
        "image_server_password=SYNTH24 image_server_user=None",
        "image_server_password=REDACTED image_server_user=None",
    ),
    (
        "{'image_url': 'http://192.0.2.1:8080/o?temp_url_sig=SYNTH25', 'image_type': 'whole-disk'}",
        "{'image_url': 'http://192.0.2.1:8080/o?temp_url_sig=REDACTED', 'image_type': 'whole-disk'}",
    ),
)

BENIGN_CORPUS = (
    "Reached target basic.target - Basic System.",
    "MPTCP token hash table entries: 65536 (order: 9, 1572864 bytes, linear)",
    "{'network_data': {'links': [{'id': 'bond0', 'ethernet_mac_address': '00:00:5e:00:53:01'}], "
    "'networks': [{'ip_address': '192.0.2.165', 'netmask': '255.255.252.0'}], "
    "'services': [{'type': 'dns', 'address': '198.51.100.8'}]}}",
    "{'image_url': 'http://192.0.2.1:8080/agent_images/00000000-0000-0000-0000-000000000000', "
    "'image_checksum': None}",
    "{'os_hash_algo': 'sha512', 'os_hash_value': '" + "ab" * 64 + "'}",
    "{'agent_token_required': True, 'agent_url': 'http://192.0.2.5:9999'}",
    "ipa-api-url=https://ironic.example.invalid BOOTIF=00:00:5e:00:53:01 ipa-debug=1",
    "systemd[1]: Starting ssh-keygen.service - OpenSSH Server Key Generation...",
    "2: eth0: link/ether 00:00:5e:00:53:01 brd ff:ff:ff:ff:ff:ff",
    "Sep 10 02:24:24 ubuntu ironic-python-agent[3620]: 2026-09-10 02:24:24.087 3620 INFO "
    "ironic_python_agent.api [-] ::ffff:192.0.2.10 - GET /v1/commands/ - 200",
    "Content-Type: application/json",
)


class RedactionRegressionTests(unittest.TestCase):
    def test_golden_corpus_redacts_exactly_as_documented(self):
        for source, expected in SECRET_CORPUS:
            with self.subTest(source=source):
                result = ipa_redactor.redact_line(source + "\n")
                self.assertEqual(result, expected + "\n")
                self.assertNotIn("SYNTH", result)

    def test_benign_lines_are_never_changed(self):
        for source in BENIGN_CORPUS:
            with self.subTest(source=source[:60]):
                self.assertEqual(ipa_redactor.redact_line(source + "\n"), source + "\n")

    def test_redaction_is_idempotent(self):
        for source, _expected in SECRET_CORPUS:
            with self.subTest(source=source):
                once = ipa_redactor.redact_line(source + "\n")
                self.assertEqual(ipa_redactor.redact_line(once), once)

    def test_line_endings_are_preserved(self):
        for ending in ("", "\n", "\r\n", "\r"):
            for source, expected in SECRET_CORPUS:
                with self.subTest(ending=repr(ending), source=source[:40]):
                    self.assertEqual(
                        ipa_redactor.redact_line(source + ending), expected + ending
                    )

    def test_url_credentials_are_redacted_when_the_scheme_is_longer_than_the_limit(self):
        # The scheme part of the pattern is capped at 32 characters to keep
        # matching linear. Without a word boundary the match simply starts later
        # inside a longer word, so the password is still found.
        for length in (31, 32, 33, 40, 100, 5000):
            with self.subTest(length=length):
                word = "a" * length
                result = ipa_redactor.redact_line(
                    "x " + word + "://user:SYNTH-pass@host/path\n"
                )
                self.assertNotIn("SYNTH", result)
                self.assertTrue(result.startswith("x " + "a" * (length - 32)))
                self.assertTrue(result.endswith("://REDACTED@host/path\n"))

    def test_url_credentials_are_redacted_behind_mixed_scheme_characters(self):
        word = "x" + "ab-c.d+" * 8
        result = ipa_redactor.redact_line(word + "://user:SYNTH-pass@host\n")
        self.assertNotIn("SYNTH", result)
        self.assertIn("://REDACTED@host", result)

    def test_secrets_on_a_line_with_several_secrets_are_all_redacted(self):
        source = (
            "agent_token=SYNTH-a rootpwd=SYNTH-b Authorization: Bearer SYNTH-c"
        )
        result = ipa_redactor.redact_line(source + "\n")
        self.assertNotIn("SYNTH", result)

    def test_private_key_block_without_end_marker_suppresses_following_lines(self):
        redactor = ipa_redactor.Redactor()
        self.assertEqual(
            redactor.redact("-----BEGIN RSA PRIVATE KEY-----\n"),
            "[REDACTED PRIVATE KEY]\n",
        )
        for line in ("body line 1\n", "body line 2\n", "agent_token=SYNTH\n"):
            self.assertIsNone(redactor.redact(line))
        self.assertTrue(redactor.in_private_key)

    def test_text_before_a_private_key_marker_is_redacted_and_kept(self):
        redactor = ipa_redactor.Redactor()
        result = redactor.redact("agent_token=SYNTH-x -----BEGIN PRIVATE KEY-----\n")
        self.assertEqual(result, "agent_token=REDACTED [REDACTED PRIVATE KEY]\n")

    def test_private_key_markers_are_case_insensitive_and_blocks_can_repeat(self):
        redactor = ipa_redactor.Redactor()
        lines = [
            "one\n",
            "-----begin private key-----\n",
            "secret-body\n",
            "-----end private key-----\n",
            "two\n",
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
            "secret-body-2\n",
            "-----END OPENSSH PRIVATE KEY-----\n",
            "three\n",
        ]
        result = [redactor.redact(line) for line in lines]
        self.assertEqual(
            [line for line in result if line is not None],
            [
                "one\n",
                "[REDACTED PRIVATE KEY]\n",
                "two\n",
                "[REDACTED PRIVATE KEY]\n",
                "three\n",
            ],
        )
        self.assertFalse(redactor.in_private_key)

    def test_each_redactor_starts_outside_a_private_key_block(self):
        first = ipa_redactor.Redactor()
        first.redact("-----BEGIN PRIVATE KEY-----\n")
        self.assertTrue(first.in_private_key)
        self.assertEqual(ipa_redactor.Redactor().redact("visible\n"), "visible\n")

    def test_unrelated_text_after_the_end_marker_line_is_not_leaked_as_state(self):
        redactor = ipa_redactor.Redactor()
        redactor.redact("-----BEGIN PRIVATE KEY-----\n")
        self.assertIsNone(redactor.redact("-----END PRIVATE KEY----- trailing\n"))
        self.assertEqual(redactor.redact("next line\n"), "next line\n")


    # The expected names below are written out on purpose. Tests that loop over
    # the code's own constants would silently shrink together with the code.

    def test_protected_names_are_pinned(self):
        """Removing a protected name must be a deliberate change to this test."""
        self.assertEqual(
            ipa_redactor.SECRET_KEYS,
            (
                "ipa-agent-token",
                "agent_token",
                "agent_secret_token",
                "agent_secret_token_pregenerated",
                "redfish_username",
                "redfish_password",
                "image_server_password",
                "configdrive",
                "root_password",
                "rootpwd",
                "sshkey",
                "kernel_append_params",
                "ssh_authorized_keys",
            ),
        )
        self.assertEqual(
            ipa_redactor.TAIL_ASSIGNMENT_SECRET_KEYS,
            ("kernel_append_params", "sshkey", "ssh_authorized_keys"),
        )
        self.assertEqual(
            ipa_redactor.AUTH_HEADER_KEYS,
            ("Authorization", "X-Auth-Token", "X-Subject-Token", "X-Service-Token"),
        )
        self.assertEqual(
            ipa_redactor.URL_QUERY_SECRET_PARAMS,
            (
                "temp_url_sig",
                "X-Amz-Signature",
                "X-Amz-Credential",
                "X-Amz-Security-Token",
                "Signature",
                "AWSAccessKeyId",
                "token",
                "sig",
            ),
        )
        self.assertEqual(
            ipa_redactor.OUTPUT_MEMBERS, ("journal", "ip_addr", "lsblk", "dmesg")
        )

    def test_each_signed_url_parameter_is_redacted(self):
        for parameter in (
            "temp_url_sig",
            "X-Amz-Signature",
            "X-Amz-Credential",
            "X-Amz-Security-Token",
            "Signature",
            "AWSAccessKeyId",
            "token",
            "sig",
        ):
            with self.subTest(parameter=parameter):
                for separator in ("?", "&", ";"):
                    source = "http://h.example.invalid/o{}{}=SYNTH&keep=1\n".format(
                        separator, parameter
                    )
                    self.assertEqual(
                        ipa_redactor.redact_line(source),
                        "http://h.example.invalid/o{}{}=REDACTED&keep=1\n".format(
                            separator, parameter
                        ),
                    )

    def test_escaped_quotes_do_not_end_a_quoted_dictionary_value(self):
        for source, expected in (
            (
                "{'rootpwd': 'ab\\'SYNTH-tail', 'k': 1}",
                "{'rootpwd': 'REDACTED', 'k': 1}",
            ),
            (
                '{"rootpwd": "ab\\"SYNTH-tail", "k": 1}',
                '{"rootpwd": \'REDACTED\', "k": 1}',
            ),
            (
                "{'rootpwd': 'ends with backslash\\\\', 'k': 1}",
                "{'rootpwd': 'REDACTED', 'k': 1}",
            ),
            (
                "{'configdrive': {'user_data': 'a\\'b} c SYNTH-tail'}, 'k': 1}",
                "{'configdrive': 'REDACTED', 'k': 1}",
            ),
        ):
            with self.subTest(source=source):
                result = ipa_redactor.redact_line(source + "\n")
                self.assertEqual(result, expected + "\n")
                self.assertNotIn("SYNTH", result)

    def test_a_secret_key_nested_inside_its_own_value_is_redacted_once(self):
        source = "{'agent_token': {'agent_token': 'SYNTH-inner'}, 'safe': 1}\n"
        self.assertEqual(
            ipa_redactor.redact_line(source),
            "{'agent_token': 'REDACTED', 'safe': 1}\n",
        )

    def test_several_entries_with_the_same_key_are_all_redacted(self):
        source = "[{'agent_token': 'SYNTH-1'}, {'agent_token': 'SYNTH-2'}, {'agent_token': ['SYNTH-3']}]\n"
        self.assertEqual(
            ipa_redactor.redact_line(source),
            "[{'agent_token': 'REDACTED'}, {'agent_token': 'REDACTED'}, {'agent_token': 'REDACTED'}]\n",
        )

    # Names that merely contain or follow a secret key are left alone.

    def test_longer_names_starting_with_a_tail_key_are_not_redacted(self):
        for source in (
            "sshkey_file=/etc/ssh/key.pub next=1\n",
            "kernel_append_params_extra=1\n",
            "ssh_authorized_keys_path: /root/.ssh\n",
            "{'sshkey_file': '/etc/ssh/key.pub', 'k': 1}\n",
        ):
            with self.subTest(source=source):
                self.assertEqual(ipa_redactor.redact_line(source), source)

    def test_longer_names_starting_with_a_token_key_are_not_redacted(self):
        for source in (
            "agent_token_required=True next=1\n",
            "rootpwd_file=/etc/rootpwd.hash\n",
            "configdrive_enabled: true\n",
            "redfish_username_prefix=x\n",
        ):
            with self.subTest(source=source):
                self.assertEqual(ipa_redactor.redact_line(source), source)

    def test_generic_token_and_signature_names_outside_a_url_query_are_not_redacted(self):
        # Documented limitation: redaction works from a known list. This pins
        # it, so widening or narrowing the behaviour is a deliberate change.
        for source in (
            "token=abc sig=def signature=ghi\n",
            "see token=abc and sig=def\n",
            "password=hunter2\n",
            "Signature: abc\n",
        ):
            with self.subTest(source=source):
                self.assertEqual(ipa_redactor.redact_line(source), source)

    # Line terminators must survive redaction of an empty or missing value.

    def test_empty_values_before_a_line_terminator_keep_the_terminator(self):
        for ending in ("\n", "\r\n", "\r"):
            for source in (
                "agent_token=",
                "agent_token = ",
                "agent_token:",
                "rootpwd=",
                "sshkey=",
                "kernel_append_params:",
                "authorization=",
                "Authorization:",
                "X-Auth-Token:",
            ):
                with self.subTest(source=source, ending=repr(ending)):
                    result = ipa_redactor.redact_line(source + ending)
                    self.assertTrue(result.endswith(ending), repr(result))
                    self.assertEqual(
                        result.count("\n") + result.count("\r"), len(ending)
                    )

    def test_a_secret_never_merges_with_the_following_line(self):
        redactor = ipa_redactor.Redactor()
        lines = ["rootpwd=\n", "next line\n", "agent_token=\r\n", "last\n"]
        result = "".join(redactor.redact(line) for line in lines)
        self.assertEqual(
            result, "rootpwd=REDACTED\nnext line\nagent_token=REDACTED\r\nlast\n"
        )


@unittest.skipUnless(hasattr(signal, "SIGALRM"), "requires SIGALRM")
class RedactionPerformanceTests(unittest.TestCase):
    """A hostile or corrupt line must not be able to stall the ipa_redactor.

    The line limit is 1 MiB, so every pattern has to stay roughly linear on
    inputs that repeat the characters it is looking for.
    """

    SIZE = 300_000
    SECONDS = 5

    def assert_fast(self, line):
        def on_timeout(signum, frame):
            raise AssertionError(
                "redaction took more than {} seconds".format(self.SECONDS)
            )

        previous = signal.signal(signal.SIGALRM, on_timeout)
        signal.alarm(self.SECONDS)
        try:
            ipa_redactor.Redactor().redact(line + "\n")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

    def test_adversarial_lines_are_redacted_in_bounded_time(self):
        n = self.SIZE
        backslash = chr(92)
        cases = {
            "hyphen runs": "a-" * (n // 2),
            "dot runs": "a." * (n // 2),
            "plus runs": "a+" * (n // 2),
            "one long word": "a" * n,
            "spaces": " " * n,
            "single quotes": "'" * n,
            "unterminated double quote": 'agent_token="' + "x" * n,
            "unterminated single quote": "rootpwd='" + "x " * (n // 2),
            "backslashes in quotes": "agent_token='" + backslash * n,
            "escaped quotes": "agent_token='" + (backslash + "'") * (n // 2),
            "repeated query marker": "?sig=" * (n // 5),
            "repeated scheme separator": "a://" * (n // 4),
            "scheme then colon runs": "http://" + "a:" * (n // 2),
            "repeated credentials": "https://u:p@" * (n // 12),
            "repeated authorization": "Authorization:" * (n // 14),
            "repeated dictionary key": "'agent_token':" * (n // 14),
            "repeated assignment": "agent_token=" * (n // 12),
            "repeated colon assignment": "sshkey:" * (n // 7),
            "open braces": "'configdrive': " + "{" * n,
            "open brackets with quotes": "'configdrive': " + "['" * (n // 2),
            "nested close braces": "'configdrive': {" + "}" * n,
            "repeated private key marker": "-----BEGIN " * (n // 11),
            "ssh key prefix": "ssh-rsa " + "A" * n,
            "many short keys": "'ab': " * (n // 6),
            "hyphen then quote": "a-'" * (n // 3),
        }
        for name, line in cases.items():
            with self.subTest(case=name):
                self.assert_fast(line)

    def test_long_prefix_glued_to_a_url_scheme_is_still_redacted(self):
        result = ipa_redactor.redact_line("a" * 100 + "http://user:SYNTH@host/x\n")
        self.assertNotIn("SYNTH", result)


if __name__ == "__main__":
    unittest.main()
