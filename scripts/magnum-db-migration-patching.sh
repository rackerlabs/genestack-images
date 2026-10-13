#!/usr/bin/env bash

patch_magnum_mysql_charset_declarations() {
    /var/lib/openstack/bin/python <<'PY'
from pathlib import Path

site_packages = next(Path("/var/lib/openstack/lib").glob("python*/site-packages"))
magnum_root = site_packages / "magnum"

replacements = {
    "db/sqlalchemy/alembic/versions/2581ebaf0cb2_initial_migration.py": [
        (
            "        mysql_ENGINE='InnoDB',\n"
            "        mysql_DEFAULT_CHARSET='UTF8'\n",
            "        mysql_ENGINE='InnoDB'\n",
        ),
        (
            "        mysql_ENGINE='InnoDB',\n"
            "        mysql_DEFAULT_CHARSET='UTF8'\n"
            "    )\n"
            "    # end Alembic commands\n",
            "        mysql_ENGINE='InnoDB'\n"
            "    )\n"
            "    # end Alembic commands\n",
        ),
    ],
    "db/sqlalchemy/alembic/versions/421102d1f2d2_create_x509keypair_table.py": [
        (
            "        mysql_ENGINE='InnoDB',\n"
            "        mysql_DEFAULT_CHARSET='UTF8'\n",
            "        mysql_ENGINE='InnoDB'\n",
        ),
    ],
    "db/sqlalchemy/alembic/versions/456126c6c9e9_create_baylock_table.py": [
        (
            "        mysql_ENGINE='InnoDB',\n"
            "        mysql_DEFAULT_CHARSET='UTF8'\n",
            "        mysql_ENGINE='InnoDB'\n",
        ),
    ],
    "db/sqlalchemy/alembic/versions/ee92b41b8809_create_quotas_table.py": [
        (
            "        mysql_ENGINE='InnoDB',\n"
            "        mysql_DEFAULT_CHARSET='UTF8'\n",
            "        mysql_ENGINE='InnoDB'\n",
        ),
    ],
    "db/sqlalchemy/models.py": [
        (
            "        return {'mysql_engine': CONF.database.mysql_engine,\n"
            "                'mysql_charset': \"utf8\"}\n",
            "        return {'mysql_engine': CONF.database.mysql_engine}\n",
        ),
    ],
}

patched = False

for relative_path, file_replacements in replacements.items():
    path = magnum_root / relative_path
    if not path.exists():
        raise SystemExit(f"{path}: expected Magnum file not found")

    text = path.read_text()
    updated = text

    for old, new in file_replacements:
        updated = updated.replace(old, new)

    if updated == text:
        print(f"{path}: no charset declarations to patch")
        continue

    path.write_text(updated)
    patched = True
    print(f"{path}: removed MySQL charset declarations")

if not patched:
    print("Magnum MySQL charset declarations already patched")
PY
}

if [ ${OS_VERSION:-master} = "stable/2025.1" ] || [ ${OS_VERSION:-master} = "stable/2026.1" ]; then
    patch_magnum_mysql_charset_declarations
fi
