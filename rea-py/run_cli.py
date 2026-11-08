"""Entry point: run rea-py straight from a checkout, no installation needed.

    python run_cli.py list-tools
    python run_cli.py inspect-pe C:\\path\\to\\app.exe
    python run_cli.py serve            # start the MCP server
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from rea_py.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
