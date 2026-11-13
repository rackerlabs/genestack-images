#!/usr/bin/env python3
"""Safely stream redacted Ironic Python Agent log bundles to stdout."""

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
import time
import uuid
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional, Pattern, Sequence, TextIO, Tuple


DEFAULT_INTERVAL = 30.0
DEFAULT_STABILITY_SECONDS = 60.0
DEFAULT_MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_TOTAL_ARCHIVE_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_MEMBER_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_LINE_BYTES = 1024 * 1024
DEFAULT_MAX_TOTAL_OUTPUT_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_OUTPUT_LINES = 100_000
DEFAULT_MAX_FORWARDED_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_MEMBERS = 1024
DEFAULT_FORWARDED_RETENTION_DAYS = 90
DEFAULT_FAILED_RETENTION_DAYS = 90
DEFAULT_CLEANUP_INTERVAL_SECONDS = 3600
DEFAULT_STATUS_INTERVAL_SECONDS = 300.0
DEFAULT_RETENTION_DRY_RUN = True
DEFAULT_MAX_PROCESSING_ATTEMPTS = 3
DEFAULT_RETRY_BACKOFF_SECONDS = 60.0
MAX_RETRY_BACKOFF_SECONDS = 3600.0
SECONDS_PER_DAY = 24 * 60 * 60
REDACTOR_TAG = "[ipa-log-redactor]"
ARCHIVE_ID_HEX_LENGTH = 16
REQUIRED_MEMBER = "journal"
OPTIONAL_MEMBERS = ("ip_addr", "lsblk", "dmesg")
OUTPUT_MEMBERS = (REQUIRED_MEMBER,) + OPTIONAL_MEMBERS
QUARANTINED_FAILED_NAME_RE = re.compile(
    r"^.+\.tar\.gz\.failed\.\d{8}T\d{6}Z(?:\.\d+)?$"
)
FAILURE_ERROR_CODES = frozenset(
    (
        "archive_too_large",
        "duplicate_member",
        "filesystem_error",
        "invalid_archive",
        "invalid_filename",
        "line_too_large",
        "member_too_large",
        "missing_journal",
        "outcome_collision",
        "forwarded_output_too_large",
        "too_many_members",
        "too_many_output_lines",
        "total_archive_too_large",
        "total_output_too_large",
        "unreadable_member",
        "unsafe_member_type",
    )
)

UUID_PATTERN = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
BUNDLE_NAME_RE = re.compile(
    r"^(?P<node_uuid>" + UUID_PATTERN + r")_"
    # Node names may contain underscores. This greedy, safe-character match
    # backtracks to the final separator followed by cleaning or an instance UUID.
    r"(?P<node_name>[A-Za-z0-9][A-Za-z0-9._-]*)_"
    r"(?P<context>cleaning|" + UUID_PATTERN + r")_"
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})\.tar\.gz$"
)

# These are all secret-bearing fields found in the reference logs or supported
# IPA/dynamic-login inputs. Keep assignment and dictionary coverage aligned.
SECRET_KEYS = (
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
)

# These fields may contain spaces. Redacting through the end of an assignment
# line is safer than risking exposure of part of an SSH key or nested arguments.
TAIL_ASSIGNMENT_SECRET_KEYS = (
    "kernel_append_params",
    "sshkey",
    "ssh_authorized_keys",
)

TOKEN_ASSIGNMENT_SECRET_KEYS = tuple(
    key for key in SECRET_KEYS if key not in TAIL_ASSIGNMENT_SECRET_KEYS
)

# Request-header names that carry credentials. They are matched in header
# (Name: value), assignment (name=value), and dictionary ('Name': 'value')
# forms. They are kept apart from SECRET_KEYS, which are IPA/Ironic fields.
AUTH_HEADER_KEYS = (
    "Authorization",
    "X-Auth-Token",
    "X-Subject-Token",
    "X-Service-Token",
)
_AUTH_HEADER_ALTERNATION = "|".join(re.escape(key) for key in AUTH_HEADER_KEYS)


def _assignment_replacement(match: "re.Match[str]") -> str:
    """Replace an assignment value while preserving its = or : separator."""
    if match.group("separator") == ":":
        return "{}: REDACTED".format(match.group("key"))
    return "{}=REDACTED".format(match.group("key"))


# Secret fields appear as key=value and, in YAML or header-like output, as
# key: value. Quoted-key dictionary forms ('key': 'value') are handled below.
# Only spaces and tabs may surround the separator. "\s" would also match the
# line terminator, so an empty value at the end of a line ("agent_token=")
# would swallow the newline and merge two log lines.
_ASSIGNMENT_SEPARATOR = r"[ \t]*(?P<separator>[=:])[ \t]*"

# Value of a key=value assignment. Order matters:
#   1. a terminated "..." or '...' value, where a backslash escapes any
#      character (so \" or \' inside the secret does not end it early);
#   2. an opening quote that is never closed. The extent of the secret is
#      unknown, so everything to the end of the line is redacted;
#   3. an unquoted value, which ends at whitespace, a quote, or "&".
_ASSIGNMENT_VALUE = (
    r"(?:\"(?:\\.|[^\"\\])*\""
    r"|'(?:\\.|[^'\\])*'"
    r"|[\"'][^\r\n]*"
    r"|[^\s\"'&]*)"
)

# The key is deliberately not anchored to a word boundary. Underscore counts as
# a word character, so "\b" would stop a prefixed name such as
# "x_agent_token=..." from matching. This is defensive: the captured IPA logs
# only use the exact key names. Because the separator must follow the key
# immediately, longer names such as "agent_token_required=..." are still left
# alone.
ASSIGNMENT_PATTERNS: Sequence[Tuple[Pattern[str], Callable[["re.Match[str]"], str]]] = tuple(
    (
        re.compile(
            r"(?P<key>" + re.escape(key) + r")" + _ASSIGNMENT_SEPARATOR + r"[^\r\n]*",
            re.IGNORECASE,
        ),
        _assignment_replacement,
    )
    for key in TAIL_ASSIGNMENT_SECRET_KEYS
) + tuple(
    (
        re.compile(
            r"(?P<key>"
            + re.escape(key)
            + r")"
            + _ASSIGNMENT_SEPARATOR
            + _ASSIGNMENT_VALUE,
            re.IGNORECASE,
        ),
        _assignment_replacement,
    )
    for key in TOKEN_ASSIGNMENT_SECRET_KEYS
)


def _dictionary_pattern(key: str) -> Pattern[str]:
    """Match a quoted dictionary key and its colon, but not the value.

    The value is located by _dictionary_value_end because it can be a string,
    a list, or a nested dictionary. A prefix inside the quotes is allowed
    ('x_agent_token') as a defensive measure; a suffix is not
    ('agent_token_required').
    """
    return re.compile(
        r"(?P<key_quote>['\"])(?P<key>[A-Za-z0-9_.\-]*"
        + re.escape(key)
        + r")(?P=key_quote)\s*:\s*",
        re.IGNORECASE,
    )


DICTIONARY_PATTERNS: Sequence[Tuple[str, Pattern[str]]] = tuple(
    (key, _dictionary_pattern(key)) for key in SECRET_KEYS + AUTH_HEADER_KEYS
)


def _quoted_string_end(text: str, start: int, limit: int) -> int:
    """Return the index after the quoted string that opens at text[start].

    A backslash escapes the next character. An unterminated string extends to
    limit, so the whole remainder of the line is treated as the secret.
    """
    quote = text[start]
    index = start + 1
    while index < limit:
        character = text[index]
        if character == "\\":
            index += 2
        elif character == quote:
            return index + 1
        else:
            index += 1
    return limit


def _dictionary_value_end(text: str, start: int, limit: int) -> int:
    """Return the index after the dictionary value that begins at text[start].

    Handles quoted strings, lists, and arbitrarily nested dictionaries or lists
    with quotes inside them. Unbalanced brackets extend to limit, redacting the
    rest of the line rather than risking a partial leak.
    """
    if start >= limit:
        return start

    first = text[start]
    if first in "'\"":
        return _quoted_string_end(text, start, limit)

    if first in "{[":
        depth = 0
        index = start
        while index < limit:
            character = text[index]
            if character in "'\"":
                index = _quoted_string_end(text, index, limit)
                continue
            if character in "{[":
                depth += 1
            elif character in "}]":
                depth -= 1
                if depth == 0:
                    return index + 1
            index += 1
        return limit

    index = start
    while index < limit and text[index] not in ",}] \t":
        index += 1
    return index


def _redact_dictionary_entries(line: str, pattern: Pattern[str]) -> str:
    """Replace the value of every matching dictionary entry in a line."""
    limit = len(line.rstrip("\r\n"))
    pieces = []
    position = 0
    for match in pattern.finditer(line):
        if match.start() < position:
            # This key sits inside a value that was already redacted.
            continue
        end = _dictionary_value_end(line, match.end(), limit)
        if end <= match.end():
            continue
        pieces.append(line[position : match.start()])
        pieces.append(
            "{quote}{key}{quote}: 'REDACTED'".format(
                quote=match.group("key_quote"), key=match.group("key")
            )
        )
        position = end
    pieces.append(line[position:])
    return "".join(pieces)

# Header lines carry values with spaces ("Bearer <token>"), so everything after
# the colon is redacted.
AUTHORIZATION_PATTERN = re.compile(
    r"(?P<header>\b(?:" + _AUTH_HEADER_ALTERNATION + r")[ \t]*:)[ \t]*[^\r\n]*",
    re.IGNORECASE,
)
# name=value form, for example a logged option or query string. The optional
# auth scheme keeps "Bearer <token>" together without consuming the rest of
# the line.
AUTH_HEADER_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?P<key>" + _AUTH_HEADER_ALTERNATION + r")[ \t]*=[ \t]*"
    r"(?:(?:Bearer|Basic|Digest|Negotiate)[ \t]+)?"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s\"'&]*)",
    re.IGNORECASE,
)
# Image download URLs (http, https, ftp, ftps, sftp, ...) can embed credentials.
# Any URL scheme is matched so that an unexpected one is not left unredacted.
# The password runs to the last @ before the path so a password containing @
# is not left partly visible.
# The scheme length is bounded on purpose. With an unbounded scheme the regex
# rescans the rest of a long run of letters, digits, "-", "." or "+" from every
# starting position, which takes quadratic time on a single 1 MiB line.
URL_CREDENTIALS_PATTERN = re.compile(
    r"(?P<scheme>[a-z][a-z0-9+.\-]{0,31}://)[^\s/@:]+:[^\s/]+@",
    re.IGNORECASE,
)
# Signed image URLs carry their credentials in the query string: Swift temp
# URLs (temp_url_sig), S3 presigned URLs (X-Amz-*), legacy S3 query
# authentication (AWSAccessKeyId, Signature), and generic token/sig parameters.
# A signature grants access to the object until it expires, so the value is
# redacted while the parameter name and the non-secret parameters (expiry,
# algorithm, date) stay visible for troubleshooting.
URL_QUERY_SECRET_PARAMS = (
    "temp_url_sig",
    "X-Amz-Signature",
    "X-Amz-Credential",
    "X-Amz-Security-Token",
    "Signature",
    "AWSAccessKeyId",
    "token",
    "sig",
)
# The parameter must directly follow ?, & or ; (the last covers "&amp;" in
# HTML-escaped URLs), so path segments, other keys that merely end in "token",
# and bare "token=" assignments outside a URL query are not touched here.
URL_QUERY_SECRET_PATTERN = re.compile(
    r"(?P<separator>[?&;])(?P<key>"
    + "|".join(re.escape(key) for key in URL_QUERY_SECRET_PARAMS)
    + r")=[^\s&#\"'<>)\],}]*",
    re.IGNORECASE,
)
SSH_PUBLIC_KEY_PATTERN = re.compile(
    r"\b(?:"
    r"ssh-(?:rsa|dss|ed25519)|"
    r"ecdsa-sha2-nistp\d+|"
    r"sk-ssh-ed25519@openssh\.com|"
    r"sk-ecdsa-sha2-nistp\d+@openssh\.com"
    r")\s+[A-Za-z0-9+/]{8,}={0,3}(?:[ \t]+[^\r\n]*)?",
    re.IGNORECASE,
)
# Covers PEM/OpenSSH blocks and PGP's "PRIVATE KEY BLOCK" armor header.
PRIVATE_KEY_BEGIN_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
    re.IGNORECASE,
)
PRIVATE_KEY_END_PATTERN = re.compile(
    r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
    re.IGNORECASE,
)


class BundleError(Exception):
    """An archive is invalid or cannot be safely processed."""

    def __init__(self, error_code: str, message: str) -> None:
        if error_code not in FAILURE_ERROR_CODES:
            raise ValueError("unknown bundle error code: {}".format(error_code))
        super().__init__(message)
        self.error_code = error_code


class OutcomeCollisionError(BundleError):
    """An archive outcome cannot be written without replacing another entry."""

    def __init__(self, message: str) -> None:
        super().__init__("outcome_collision", message)


class OutputBudget:
    """Bound the actual archive payload written to stdout."""

    def __init__(self, max_lines: int, max_bytes: int) -> None:
        self.max_lines = max_lines
        self.max_bytes = max_bytes
        self.lines = 0
        self.bytes = 0

    def write(self, output: TextIO, record: str) -> None:
        """Write one complete record if it fits within both output limits."""
        record_bytes = len(record.encode("utf-8"))
        if self.lines + 1 > self.max_lines:
            raise BundleError(
                "too_many_output_lines",
                "archive output exceeds the configured line limit",
            )
        if self.bytes + record_bytes > self.max_bytes:
            raise BundleError(
                "forwarded_output_too_large",
                "archive output exceeds the configured byte limit",
            )
        output.write(record)
        self.lines += 1
        self.bytes += record_bytes


def redact_line(line: str) -> str:
    """Return one non-PEM log line with secret-bearing values redacted."""
    for pattern, replacement in ASSIGNMENT_PATTERNS:
        line = pattern.sub(replacement, line)

    for _key, pattern in DICTIONARY_PATTERNS:
        line = _redact_dictionary_entries(line, pattern)

    line = AUTHORIZATION_PATTERN.sub(r"\g<header> REDACTED", line)
    line = AUTH_HEADER_ASSIGNMENT_PATTERN.sub(r"\g<key>=REDACTED", line)
    line = URL_CREDENTIALS_PATTERN.sub(r"\g<scheme>REDACTED@", line)
    line = URL_QUERY_SECRET_PATTERN.sub(r"\g<separator>\g<key>=REDACTED", line)
    line = SSH_PUBLIC_KEY_PATTERN.sub("SSH_PUBLIC_KEY_REDACTED", line)
    return line


class Redactor:
    """Stateful redactor for line-oriented logs, including PEM blocks."""

    def __init__(self) -> None:
        self.in_private_key = False

    def redact(self, line: str) -> Optional[str]:
        """Redact one line, or suppress it when inside a private-key block."""
        if self.in_private_key:
            if PRIVATE_KEY_END_PATTERN.search(line):
                self.in_private_key = False
            return None

        begin = PRIVATE_KEY_BEGIN_PATTERN.search(line)
        if begin is not None:
            self.in_private_key = PRIVATE_KEY_END_PATTERN.search(line, begin.end()) is None
            newline = "\n" if line.endswith(("\n", "\r")) else ""
            safe_prefix = redact_line(line[: begin.start()].rstrip())
            separator = " " if safe_prefix else ""
            return "{}{}[REDACTED PRIVATE KEY]{}".format(
                safe_prefix, separator, newline
            )

        return redact_line(line)


def parse_bundle_name(path: Path) -> Tuple[str, str]:
    """Validate an Ironic bundle name and return node name and log context."""
    name = path.name
    if name.endswith(".processing"):
        name = name[: -len(".processing")]

    match = BUNDLE_NAME_RE.fullmatch(name)
    if not match:
        raise BundleError("invalid_filename", "unexpected bundle filename")

    try:
        uuid.UUID(match.group("node_uuid"))
        if match.group("context") != "cleaning":
            uuid.UUID(match.group("context"))
        time.strptime(match.group("timestamp"), "%Y-%m-%d-%H-%M-%S")
    except ValueError as exc:
        raise BundleError(
            "invalid_filename", "invalid UUID or timestamp in bundle filename"
        ) from exc

    return match.group("node_name"), match.group("context")


def original_archive_name(claimed_path: Path) -> str:
    """Return the original bundle filename without the processing suffix."""
    name = claimed_path.name
    if name.endswith(".processing"):
        name = name[: -len(".processing")]
    return name


def archive_id_for(claimed_path: Path) -> str:
    """Return a short ID that remains stable when the same bundle is retried."""
    digest = hashlib.sha256(
        original_archive_name(claimed_path).encode("utf-8")
    ).hexdigest()
    return digest[:ARCHIVE_ID_HEX_LENGTH]


def emit_lifecycle_event(
    output: TextIO,
    event: str,
    archive_id: str,
    archive_name: str,
    attempt_id: str,
    error_code: Optional[str] = None,
) -> None:
    """Write one structured archive lifecycle record to stdout.

    The potentially long bundle filename is emitted only at archive_start.
    Later records correlate through archive_id and attempt_id.
    """
    record = {
        "event": event,
        "archive_id": archive_id,
        "attempt_id": attempt_id,
        "status": {
            "archive_start": "processing",
            "archive_complete": "processed",
            "archive_failed": "failed",
        }[event],
    }
    if event == "archive_start":
        record["archive_name"] = archive_name
    if event == "archive_failed":
        if error_code not in FAILURE_ERROR_CODES:
            raise ValueError("archive_failed requires a controlled error code")
        record["error_code"] = error_code
    elif error_code is not None:
        raise ValueError("error_code is valid only for archive_failed")
    output.write(
        "{} {}\n".format(
            REDACTOR_TAG,
            json.dumps(record, separators=(",", ":")),
        )
    )
    output.flush()


def emit_status_event(output: TextIO, event: str, **safe_fields: object) -> None:
    """Emit a structured, non-error status record."""
    record = {"event": event}
    record.update(safe_fields)
    output.write(
        "{} {}\n".format(
            REDACTOR_TAG,
            json.dumps(record, separators=(",", ":")),
        )
    )
    output.flush()


def archive_inventory(logs_dir: Path) -> Dict[str, int]:
    """Return archive counts suitable for startup and heartbeat records."""
    return {
        "pending_archives": len(list(logs_dir.glob("*.tar.gz"))),
        "processing_archives": len(list(logs_dir.glob("*.tar.gz.processing"))),
        "forwarded_archives": len(list(logs_dir.glob("*.tar.gz.forwarded"))),
        "failed_archives": len(list(logs_dir.glob("*.tar.gz.failed*"))),
    }


def emit_operational_event(
    output: TextIO,
    event: str,
    error_code: str,
    **safe_fields: str,
) -> None:
    """Emit a JSON diagnostic without raw exception text or unescaped paths."""
    record = {"event": event, "error_code": error_code}
    record.update(safe_fields)
    output.write(
        "{} {}\n".format(
            REDACTOR_TAG,
            json.dumps(record, separators=(",", ":")),
        )
    )
    output.flush()


def selected_members(
    archive: tarfile.TarFile,
    max_archive_members: int,
    max_total_archive_bytes: int,
    max_member_bytes: int,
    max_total_output_bytes: int,
) -> Dict[str, tarfile.TarInfo]:
    """Return validated, allow-listed regular-file members from an archive."""
    selected: Dict[str, tarfile.TarInfo] = {}
    member_count = 0
    total_archive_bytes = 0
    total_output_bytes = 0

    for member in archive:
        member_count += 1
        if member_count > max_archive_members:
            raise BundleError("too_many_members", "archive contains too many members")
        if member.size < 0:
            raise BundleError(
                "invalid_archive",
                "archive member {!r} has an invalid size".format(member.name),
            )
        total_archive_bytes += member.size
        if total_archive_bytes > max_total_archive_bytes:
            raise BundleError(
                "total_archive_too_large",
                "archive members total uncompressed size {} exceeds limit {} bytes".format(
                    total_archive_bytes, max_total_archive_bytes
                )
            )
        if member.name not in OUTPUT_MEMBERS:
            continue
        if member.name in selected:
            raise BundleError(
                "duplicate_member",
                "archive contains duplicate {!r} member".format(member.name),
            )
        if not member.isfile():
            raise BundleError(
                "unsafe_member_type",
                "archive member {!r} is not a regular file".format(member.name),
            )
        if member.size < 0 or member.size > max_member_bytes:
            raise BundleError(
                "member_too_large",
                "archive member {!r} exceeds the size limit".format(member.name),
            )
        total_output_bytes += member.size
        if total_output_bytes > max_total_output_bytes:
            raise BundleError(
                "total_output_too_large",
                "selected archive members total {} exceeds limit {} bytes".format(
                    total_output_bytes, max_total_output_bytes
                )
            )
        selected[member.name] = member

    if REQUIRED_MEMBER not in selected:
        raise BundleError("missing_journal", "archive has no journal member")
    return selected


def stream_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    prefix: str,
    archive_id: str,
    output: TextIO,
    max_line_bytes: int,
    output_budget: OutputBudget,
) -> None:
    """Stream bounded raw lines through redaction without writing them to disk."""
    extracted = archive.extractfile(member)
    if extracted is None:
        raise BundleError(
            "unreadable_member",
            "could not read archive member {!r}".format(member.name),
        )

    redactor = Redactor()
    with extracted:
        while True:
            # Read one byte beyond the configured bound so a member without
            # newlines cannot be split into several apparently valid records.
            raw_line = extracted.readline(max_line_bytes + 1)
            if not raw_line:
                break
            if len(raw_line) > max_line_bytes:
                raise BundleError(
                    "line_too_large",
                    "archive member {!r} contains a line exceeding {} bytes".format(
                        member.name, max_line_bytes
                    ),
                )

            line = raw_line.decode("utf-8", errors="replace")
            redacted = redactor.redact(line)
            if redacted is None:
                continue
            # Keep payload records compact: the archive_start record contains
            # the full bundle name (including the instance UUID), while this
            # short archive ID links every content line back to it. Empty spacer
            # records are avoided because collectors may discard or collapse them.
            record = "{} [archive={}] [{}] {}".format(
                prefix, archive_id, member.name, redacted
            )
            if not redacted.endswith(("\n", "\r")):
                record += "\n"
            output_budget.write(output, record)


def outcome_path(claimed_path: Path, outcome: str) -> Path:
    """Return the final archive path for a claimed .processing file."""
    name = claimed_path.name
    if name.endswith(".processing"):
        name = name[: -len(".processing")]
    return claimed_path.with_name("{}.{}".format(name, outcome))


def path_entry_exists(path: Path) -> bool:
    """Return whether a path entry exists, including a dangling symlink."""
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def move_without_overwrite(source: Path, destination: Path) -> None:
    """Move a regular file in one directory without replacing any path entry."""
    try:
        os.link(source, destination, follow_symlinks=False)
    except FileExistsError as exc:
        raise OutcomeCollisionError(
            "outcome path already exists: {}".format(destination)
        ) from exc
    source.unlink()


def mark_outcome(
    claimed_path: Path,
    outcome: str,
    outcome_time: Optional[float] = None,
) -> Path:
    """Atomically mark an archive and start retention from this transition."""
    destination = outcome_path(claimed_path, outcome)
    # Moving preserves mtime. Refresh it first so retention is measured from
    # forwarding/failure rather than from the original bundle creation time.
    timestamp = time.time() if outcome_time is None else outcome_time
    os.utime(
        claimed_path,
        (timestamp, timestamp),
        follow_symlinks=False,
    )
    move_without_overwrite(claimed_path, destination)
    return destination


def quarantine_archive(
    claimed_path: Path,
    error_output: TextIO,
    quarantine_time: Optional[float] = None,
) -> Path:
    """Move a colliding archive to a unique failed name and emit an alert."""
    timestamp = time.time() if quarantine_time is None else quarantine_time
    timestamp_text = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(timestamp))
    failed_path = outcome_path(claimed_path, "failed")
    destination = failed_path.with_name("{}.{}".format(failed_path.name, timestamp_text))
    counter = 1

    os.utime(
        claimed_path,
        (timestamp, timestamp),
        follow_symlinks=False,
    )
    while True:
        try:
            move_without_overwrite(claimed_path, destination)
            break
        except OutcomeCollisionError:
            destination = failed_path.with_name(
                "{}.{}.{}".format(failed_path.name, timestamp_text, counter)
            )
            counter += 1
    emit_operational_event(
        error_output,
        "archive_quarantined",
        "outcome_collision",
        archive_id=archive_id_for(claimed_path),
        archive_name=original_archive_name(claimed_path),
        quarantine_name=destination.name,
    )
    return destination


def outcome_archives(logs_dir: Path, outcome: str) -> Iterable[Path]:
    """Yield normal outcomes and validated timestamped failed quarantines."""
    pattern = "*.tar.gz.{}*".format(outcome)
    for path in sorted(logs_dir.glob(pattern)):
        if path.name.endswith(".tar.gz.{}".format(outcome)):
            yield path
        elif outcome == "failed" and QUARANTINED_FAILED_NAME_RE.fullmatch(path.name):
            yield path


def cleanup_expired_archives(
    logs_dir: Path,
    output: TextIO,
    error_output: TextIO,
    forwarded_retention_days: int,
    failed_retention_days: int,
    dry_run: bool = DEFAULT_RETENTION_DRY_RUN,
    now: Optional[float] = None,
) -> int:
    """Handle expired outcome archives and return the number removed.

    Retention age starts from the mtime recorded by mark_outcome. A retention
    value of zero disables cleanup for that outcome. Dry-run mode reports
    eligible files without deleting them. Only regular files with an exact
    outcome suffix, or a validated timestamped failed-quarantine suffix, are
    eligible; symlinks are ignored.
    """
    current_time = time.time() if now is None else now
    removed = 0

    for outcome, retention_days in (
        ("forwarded", forwarded_retention_days),
        ("failed", failed_retention_days),
    ):
        if retention_days == 0:
            continue

        cutoff = current_time - (retention_days * SECONDS_PER_DAY)
        for path in outcome_archives(logs_dir, outcome):
            try:
                metadata = path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_mtime > cutoff:
                    continue
                if dry_run:
                    print(
                        "{} retention dry-run: would remove expired {} archive: {}".format(
                            REDACTOR_TAG, outcome, path
                        ),
                        file=output,
                        flush=True,
                    )
                    continue
                path.unlink()
            except FileNotFoundError:
                continue
            except OSError:
                emit_operational_event(
                    error_output,
                    "retention_cleanup_failed",
                    "filesystem_error",
                    outcome=outcome,
                )
                continue

            print(
                "{} removed expired {} archive: {}".format(
                    REDACTOR_TAG, outcome, path
                ),
                file=output,
                flush=True,
            )
            removed += 1

    return removed


def process_claimed_archive(
    claimed_path: Path,
    output: TextIO,
    error_output: TextIO,
    max_archive_members: int,
    max_archive_bytes: int,
    max_total_archive_bytes: int,
    max_member_bytes: int,
    max_line_bytes: int,
    max_total_output_bytes: int,
    max_output_lines: int,
    max_forwarded_bytes: int,
) -> bool:
    """Process one claimed archive and mark it forwarded or failed."""
    archive_name = original_archive_name(claimed_path)
    archive_id = archive_id_for(claimed_path)
    attempt_id = str(uuid.uuid4())
    output_budget = OutputBudget(max_output_lines, max_forwarded_bytes)
    try:
        emit_lifecycle_event(
            output,
            "archive_start",
            archive_id,
            archive_name,
            attempt_id,
        )
        collisions = [
            path
            for path in (
                outcome_path(claimed_path, "forwarded"),
                outcome_path(claimed_path, "failed"),
            )
            if path_entry_exists(path)
        ]
        if collisions:
            quarantine_archive(
                claimed_path,
                error_output,
            )
            emit_lifecycle_event(
                output,
                "archive_failed",
                archive_id,
                archive_name,
                attempt_id,
                "outcome_collision",
            )
            return False

        archive_size = claimed_path.stat().st_size
        if archive_size > max_archive_bytes:
            raise BundleError(
                "archive_too_large",
                "compressed archive size {} exceeds limit {} bytes".format(
                    archive_size, max_archive_bytes
                )
            )

        node_name, _context = parse_bundle_name(claimed_path)
        prefix = "[{}]".format(node_name)

        with tarfile.open(claimed_path, mode="r:gz") as archive:
            members = selected_members(
                archive,
                max_archive_members,
                max_total_archive_bytes,
                max_member_bytes,
                max_total_output_bytes,
            )
            for member_name in OUTPUT_MEMBERS:
                member = members.get(member_name)
                if member is None:
                    continue
                output_budget.write(
                    output,
                    "{} [archive_id={}] ===================== {} =====================\n".format(
                        REDACTOR_TAG, archive_id, member_name
                    ),
                )
                stream_member(
                    archive,
                    member,
                    prefix,
                    archive_id,
                    output,
                    max_line_bytes,
                    output_budget,
                )
        output.flush()
        # Mark the local outcome before announcing completion. This prevents a
        # failed outcome transition from producing a false completion record.
        mark_outcome(claimed_path, "forwarded")
        # Complete means every selected, redacted line was written and the
        # archive was locally marked forwarded. It does not claim downstream
        # persistence by the container runtime or central logging platform.
        emit_lifecycle_event(
            output,
            "archive_complete",
            archive_id,
            archive_name,
            attempt_id,
        )
        return True
    except BrokenPipeError:
        raise
    except OutcomeCollisionError:
        try:
            quarantine_archive(
                claimed_path,
                error_output,
            )
        except OSError:
            emit_operational_event(
                error_output,
                "outcome_transition_failed",
                "filesystem_error",
                archive_id=archive_id,
            )
        emit_lifecycle_event(
            output,
            "archive_failed",
            archive_id,
            archive_name,
            attempt_id,
            "outcome_collision",
        )
        return False
    except (BundleError, OSError, tarfile.TarError) as exc:
        if isinstance(exc, BundleError):
            failure_error_code = exc.error_code
        elif isinstance(exc, tarfile.TarError):
            failure_error_code = "invalid_archive"
        else:
            failure_error_code = "filesystem_error"
        emit_operational_event(
            error_output,
            "archive_processing_failed",
            failure_error_code,
            archive_id=archive_id,
        )
        try:
            mark_outcome(claimed_path, "failed")
        except OutcomeCollisionError:
            try:
                quarantine_archive(
                    claimed_path,
                    error_output,
                )
            except OSError:
                emit_operational_event(
                    error_output,
                    "outcome_transition_failed",
                    "filesystem_error",
                    archive_id=archive_id,
                )
        except OSError:
            emit_operational_event(
                error_output,
                "outcome_transition_failed",
                "filesystem_error",
                archive_id=archive_id,
            )
        emit_lifecycle_event(
            output,
            "archive_failed",
            archive_id,
            archive_name,
            attempt_id,
            failure_error_code,
        )
        return False


def claim_archive(path: Path) -> Optional[Path]:
    """Atomically move a new archive to its processing name."""
    claimed = path.with_name(path.name + ".processing")
    if claimed.exists():
        return None
    try:
        path.rename(claimed)
    except FileNotFoundError:
        return None
    return claimed


def discover_claimed_archives(
    logs_dir: Path,
    stability_observations: Dict[Path, Tuple[int, int, float]],
    stability_seconds: float,
    scan_time: Optional[float] = None,
) -> Iterable[Path]:
    """Yield interrupted work, then claim bundles stable across scans."""
    observed_at = time.monotonic() if scan_time is None else scan_time

    for path in sorted(logs_dir.glob("*.tar.gz.processing")):
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(metadata.st_mode):
            yield path

    present_archives = set()
    for path in sorted(logs_dir.glob("*.tar.gz")):
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(metadata.st_mode):
            continue

        present_archives.add(path)
        signature = (metadata.st_size, metadata.st_mtime_ns)
        previous = stability_observations.get(path)
        if stability_seconds > 0:
            if previous is None or previous[:2] != signature:
                stability_observations[path] = (
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    observed_at,
                )
                continue
            if observed_at - previous[2] < stability_seconds:
                continue

        claimed = claim_archive(path)
        if claimed is not None:
            stability_observations.pop(path, None)
            yield claimed

    for missing_path in set(stability_observations) - present_archives:
        stability_observations.pop(missing_path, None)


def process_available(
    logs_dir: Path,
    output: TextIO,
    error_output: TextIO,
    max_archive_members: int,
    max_archive_bytes: int,
    max_total_archive_bytes: int,
    max_member_bytes: int,
    max_line_bytes: int,
    max_total_output_bytes: int,
    max_output_lines: int,
    max_forwarded_bytes: int,
    stability_observations: Optional[Dict[Path, Tuple[int, int, float]]] = None,
    stability_seconds: float = DEFAULT_STABILITY_SECONDS,
    scan_time: Optional[float] = None,
    retry_state: Optional[Dict[Path, Tuple[int, float]]] = None,
    max_processing_attempts: int = DEFAULT_MAX_PROCESSING_ATTEMPTS,
    retry_backoff_seconds: float = DEFAULT_RETRY_BACKOFF_SECONDS,
) -> int:
    """Process all currently available bundles and return their count.

    A claimed archive that is still present after processing could not be
    moved to an outcome name (for example, the filesystem rejected the rename).
    Rediscovering it on every scan would stream the same content again each
    time, so retry_state records (attempts, next_retry_time) per path. Retries
    back off exponentially and stop after max_processing_attempts until the
    process restarts. Pass the same dictionary on every scan to keep this state.
    """
    if stability_observations is None:
        stability_observations = {}
    if retry_state is None:
        retry_state = {}
    current_time = time.monotonic() if scan_time is None else scan_time

    processed = 0
    for claimed_path in discover_claimed_archives(
        logs_dir,
        stability_observations,
        stability_seconds,
        scan_time,
    ):
        previous = retry_state.get(claimed_path)
        if previous is not None:
            previous_attempts, next_retry_time = previous
            if previous_attempts >= max_processing_attempts:
                continue
            if current_time < next_retry_time:
                continue

        process_claimed_archive(
            claimed_path,
            output,
            error_output,
            max_archive_members,
            max_archive_bytes,
            max_total_archive_bytes,
            max_member_bytes,
            max_line_bytes,
            max_total_output_bytes,
            max_output_lines,
            max_forwarded_bytes,
        )
        processed += 1

        if not path_entry_exists(claimed_path):
            retry_state.pop(claimed_path, None)
            continue

        # The outcome transition failed and the archive is still claimed.
        attempts = (previous[0] if previous is not None else 0) + 1
        delay = min(
            retry_backoff_seconds * (2 ** (attempts - 1)),
            MAX_RETRY_BACKOFF_SECONDS,
        )
        retry_state[claimed_path] = (attempts, current_time + delay)
        if attempts >= max_processing_attempts:
            emit_operational_event(
                error_output,
                "archive_retry_limit_reached",
                "filesystem_error",
                archive_id=archive_id_for(claimed_path),
            )

    for stale_path in [path for path in retry_state if not path_entry_exists(path)]:
        del retry_state[stale_path]
    return processed


def positive_number(value: str, value_type, name: str):
    try:
        parsed = value_type(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("{} must be a number".format(name)) from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("{} must be greater than zero".format(name))
    return parsed


def non_negative_number(value: str, value_type, name: str):
    try:
        parsed = value_type(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("{} must be a number".format(name)) from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("{} must be zero or greater".format(name))
    return parsed


def boolean_value(value: str, name: str) -> bool:
    normalized = value.strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    raise argparse.ArgumentTypeError(
        "{} must be true or false".format(name)
    )


def logs_dir_path(value: str) -> Path:
    """Parse a logs directory, rejecting blank values.

    Path("") silently becomes the current directory, which would make the
    redactor watch an unrelated location such as the container's /app.
    """
    if not value.strip():
        raise argparse.ArgumentTypeError("logs-dir must not be empty")
    return Path(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    # A blank LOGS_DIR (for example, an unset Helm value rendered as "") is
    # treated exactly like an unset variable.
    logs_dir_from_environment = os.environ.get("LOGS_DIR", "").strip() or None
    parser.add_argument(
        "--logs-dir",
        type=logs_dir_path,
        default=logs_dir_from_environment,
        required=logs_dir_from_environment is None,
        help="directory containing IPA .tar.gz bundles (or set LOGS_DIR)",
    )
    parser.add_argument(
        "--interval",
        type=lambda value: positive_number(value, float, "interval"),
        default=positive_number(os.environ.get("INTERVAL", str(DEFAULT_INTERVAL)), float, "interval"),
        help="seconds between scans (default: %(default)s)",
    )
    parser.add_argument(
        "--stability-seconds",
        type=lambda value: non_negative_number(value, float, "stability-seconds"),
        default=non_negative_number(
            os.environ.get("STABILITY_SECONDS", str(DEFAULT_STABILITY_SECONDS)),
            float,
            "stability-seconds",
        ),
        help=(
            "seconds size and modification time must remain unchanged across scans; "
            "0 disables the wait (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--status-interval-seconds",
        type=lambda value: non_negative_number(
            value, float, "status-interval-seconds"
        ),
        default=non_negative_number(
            os.environ.get(
                "STATUS_INTERVAL_SECONDS",
                str(DEFAULT_STATUS_INTERVAL_SECONDS),
            ),
            float,
            "status-interval-seconds",
        ),
        help=(
            "seconds between status heartbeat records; 0 disables heartbeats "
            "(default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--max-archive-bytes",
        type=lambda value: positive_number(value, int, "max-archive-bytes"),
        default=positive_number(
            os.environ.get("MAX_ARCHIVE_BYTES", str(DEFAULT_MAX_ARCHIVE_BYTES)),
            int,
            "max-archive-bytes",
        ),
        help="maximum compressed size of an input archive (default: %(default)s)",
    )
    parser.add_argument(
        "--max-member-bytes",
        type=lambda value: positive_number(value, int, "max-member-bytes"),
        default=positive_number(
            os.environ.get("MAX_MEMBER_BYTES", str(DEFAULT_MAX_MEMBER_BYTES)),
            int,
            "max-member-bytes",
        ),
        help="maximum uncompressed size of each selected member (default: %(default)s)",
    )
    parser.add_argument(
        "--max-line-bytes",
        type=lambda value: positive_number(value, int, "max-line-bytes"),
        default=positive_number(
            os.environ.get("MAX_LINE_BYTES", str(DEFAULT_MAX_LINE_BYTES)),
            int,
            "max-line-bytes",
        ),
        help=(
            "maximum raw size of one selected-member line, including its newline "
            "(default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--max-total-archive-bytes",
        type=lambda value: positive_number(value, int, "max-total-archive-bytes"),
        default=positive_number(
            os.environ.get(
                "MAX_TOTAL_ARCHIVE_BYTES",
                str(DEFAULT_MAX_TOTAL_ARCHIVE_BYTES),
            ),
            int,
            "max-total-archive-bytes",
        ),
        help=(
            "maximum combined uncompressed size of all archive members "
            "(default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--max-total-output-bytes",
        type=lambda value: positive_number(value, int, "max-total-output-bytes"),
        default=positive_number(
            os.environ.get(
                "MAX_TOTAL_OUTPUT_BYTES",
                str(DEFAULT_MAX_TOTAL_OUTPUT_BYTES),
            ),
            int,
            "max-total-output-bytes",
        ),
        help=(
            "maximum combined uncompressed size of selected members "
            "(default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--max-output-lines",
        type=lambda value: positive_number(value, int, "max-output-lines"),
        default=positive_number(
            os.environ.get("MAX_OUTPUT_LINES", str(DEFAULT_MAX_OUTPUT_LINES)),
            int,
            "max-output-lines",
        ),
        help=(
            "maximum archive payload records written to stdout, including "
            "section records (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--max-forwarded-bytes",
        type=lambda value: positive_number(value, int, "max-forwarded-bytes"),
        default=positive_number(
            os.environ.get(
                "MAX_FORWARDED_BYTES",
                str(DEFAULT_MAX_FORWARDED_BYTES),
            ),
            int,
            "max-forwarded-bytes",
        ),
        help=(
            "maximum UTF-8 bytes of prefixed archive payload written to stdout "
            "(default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--max-archive-members",
        type=lambda value: positive_number(value, int, "max-archive-members"),
        default=positive_number(
            os.environ.get("MAX_ARCHIVE_MEMBERS", str(DEFAULT_MAX_ARCHIVE_MEMBERS)),
            int,
            "max-archive-members",
        ),
        help="maximum number of members allowed in an archive",
    )
    parser.add_argument(
        "--forwarded-retention-days",
        type=lambda value: non_negative_number(value, int, "forwarded-retention-days"),
        default=non_negative_number(
            os.environ.get(
                "FORWARDED_RETENTION_DAYS",
                str(DEFAULT_FORWARDED_RETENTION_DAYS),
            ),
            int,
            "forwarded-retention-days",
        ),
        help="days to retain .forwarded archives; 0 disables deletion (default: %(default)s)",
    )
    parser.add_argument(
        "--failed-retention-days",
        type=lambda value: non_negative_number(value, int, "failed-retention-days"),
        default=non_negative_number(
            os.environ.get("FAILED_RETENTION_DAYS", str(DEFAULT_FAILED_RETENTION_DAYS)),
            int,
            "failed-retention-days",
        ),
        help="days to retain .failed archives; 0 disables deletion (default: %(default)s)",
    )
    parser.add_argument(
        "--cleanup-interval-seconds",
        type=lambda value: positive_number(value, int, "cleanup-interval-seconds"),
        default=positive_number(
            os.environ.get(
                "CLEANUP_INTERVAL_SECONDS",
                str(DEFAULT_CLEANUP_INTERVAL_SECONDS),
            ),
            int,
            "cleanup-interval-seconds",
        ),
        help="seconds between expired-archive cleanup checks (default: %(default)s)",
    )
    parser.add_argument(
        "--retention-dry-run",
        action=argparse.BooleanOptionalAction,
        default=boolean_value(
            os.environ.get(
                "RETENTION_DRY_RUN",
                str(DEFAULT_RETENTION_DRY_RUN),
            ),
            "retention-dry-run",
        ),
        help="report expired archives without deleting them (default: %(default)s)",
    )
    parser.add_argument(
        "--max-processing-attempts",
        type=lambda value: positive_number(value, int, "max-processing-attempts"),
        default=positive_number(
            os.environ.get(
                "MAX_PROCESSING_ATTEMPTS",
                str(DEFAULT_MAX_PROCESSING_ATTEMPTS),
            ),
            int,
            "max-processing-attempts",
        ),
        help=(
            "times an archive that cannot be moved to an outcome name is "
            "processed before retries stop until restart (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--retry-backoff-seconds",
        type=lambda value: non_negative_number(value, float, "retry-backoff-seconds"),
        default=non_negative_number(
            os.environ.get(
                "RETRY_BACKOFF_SECONDS",
                str(DEFAULT_RETRY_BACKOFF_SECONDS),
            ),
            float,
            "retry-backoff-seconds",
        ),
        help=(
            "initial delay before retrying an archive stuck in .processing; "
            "doubles per attempt, capped at one hour (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="process one stable batch and exit",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.logs_dir.is_dir():
        emit_operational_event(
            sys.stderr,
            "startup_failed",
            "invalid_logs_dir",
        )
        return 2

    try:
        inventory = archive_inventory(args.logs_dir)
        emit_status_event(
            sys.stdout,
            "redactor_started",
            status="watching",
            logs_dir=str(args.logs_dir),
            **inventory,
        )
        next_status = time.monotonic() + args.status_interval_seconds
        next_cleanup = 0.0
        stability_observations: Dict[Path, Tuple[int, int, float]] = {}
        retry_state: Dict[Path, Tuple[int, float]] = {}
        while True:
            process_available(
                args.logs_dir,
                sys.stdout,
                sys.stderr,
                args.max_archive_members,
                args.max_archive_bytes,
                args.max_total_archive_bytes,
                args.max_member_bytes,
                args.max_line_bytes,
                args.max_total_output_bytes,
                args.max_output_lines,
                args.max_forwarded_bytes,
                stability_observations,
                args.stability_seconds,
                retry_state=retry_state,
                max_processing_attempts=args.max_processing_attempts,
                retry_backoff_seconds=args.retry_backoff_seconds,
            )
            monotonic_now = time.monotonic()
            if monotonic_now >= next_cleanup:
                cleanup_expired_archives(
                    args.logs_dir,
                    sys.stdout,
                    sys.stderr,
                    args.forwarded_retention_days,
                    args.failed_retention_days,
                    args.retention_dry_run,
                )
                next_cleanup = monotonic_now + args.cleanup_interval_seconds
            if (
                args.status_interval_seconds > 0
                and monotonic_now >= next_status
            ):
                emit_status_event(
                    sys.stdout,
                    "redactor_status",
                    status="watching",
                    **archive_inventory(args.logs_dir),
                )
                next_status = monotonic_now + args.status_interval_seconds
            # In one-shot mode, keep scanning while new archives are waiting
            # out their stability window instead of exiting after observation.
            if args.once and not stability_observations:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except BrokenPipeError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
