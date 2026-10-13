#!/usr/bin/env bash

patch_magnum_nodegroups_v2_migration() {
    local migration_file

    migration_file="$(find /var/lib/openstack/lib/python*/site-packages/magnum/db/sqlalchemy/alembic/versions \
        -name 'c04e925e65c2_nodegroups_v2.py' \
        -print \
        -quit)"

    if [ -z "${migration_file}" ]; then
        echo "Magnum nodegroups_v2 migration not found; skipping patch"
        return 0
    fi

    /var/lib/openstack/bin/python - "${migration_file}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()

if "_add_column_if_missing" in text:
    print(f"{path}: nodegroups_v2 migration already patched")
    raise SystemExit(0)

old = """\
def upgrade():
    op.add_column('nodegroup', sa.Column('stack_id', String(255)))
    op.add_column('nodegroup', sa.Column('status', String(20)))
    op.add_column('nodegroup', sa.Column('status_reason', sa.Text()))
    op.add_column('nodegroup', sa.Column('version', String(20)))
"""

new = """\
def _has_column(table_name, column_name):
    inspector = sa.inspect(op.get_bind())
    return column_name in {column['name']
                           for column in inspector.get_columns(table_name)}


def _add_column_if_missing(table_name, column):
    if not _has_column(table_name, column.name):
        op.add_column(table_name, column)


def upgrade():
    _add_column_if_missing('nodegroup', sa.Column('stack_id', String(255)))
    _add_column_if_missing('nodegroup', sa.Column('status', String(20)))
    _add_column_if_missing('nodegroup', sa.Column('status_reason', sa.Text()))
    _add_column_if_missing('nodegroup', sa.Column('version', String(20)))
"""

if old not in text:
    raise SystemExit(f"{path}: expected nodegroups_v2 migration block not found")

path.write_text(text.replace(old, new, 1))
print(f"{path}: patched nodegroups_v2 migration")
PY
}

if [ ${OS_VERSION:-master} = "stable/2025.1" ] || [ ${OS_VERSION:-master} = "stable/2026.1" ]; then
    patch_magnum_nodegroups_v2_migration
fi
