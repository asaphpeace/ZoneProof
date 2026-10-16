"""C3: the schema step is a separate release step; replicas can start without running it."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_entrypoint_can_skip_or_run_only_the_migration_step():
    text = (ROOT / "entrypoint.sh").read_text(encoding="utf-8")
    assert 'RUN_MIGRATIONS:-true' in text and '"$1" = "migrate"' in text
    assert "alembic" not in text  # the schema logic lives in migrate.sh only
    assert "alembic upgrade head" in (ROOT / "migrate.sh").read_text(encoding="utf-8")


def test_dockerfile_makes_both_scripts_executable():
    assert "chmod +x entrypoint.sh migrate.sh" in (ROOT / "Dockerfile").read_text(encoding="utf-8")


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX shell")
@pytest.mark.parametrize("script", ["entrypoint.sh", "migrate.sh"])
def test_scripts_parse(script):
    assert subprocess.run(["sh", "-n", str(ROOT / script)]).returncode == 0
