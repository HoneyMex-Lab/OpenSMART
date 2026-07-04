import subprocess
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent / "scripts"


def run_script(name: str, args: list[str] | None = None) -> str:
    script = SCRIPT_DIR / name
    if not script.is_file():
        raise FileNotFoundError(f"Missing script: {name}")
    result = subprocess.run(
        [str(script), *(args or [])],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.stdout.strip()
