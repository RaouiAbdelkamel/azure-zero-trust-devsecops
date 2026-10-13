"""Remove source snippets from scanner reports before public artifact upload."""

import json
from pathlib import Path

from policy import redact


def main():
    for path in Path(".reports").rglob("*"):
        if path.is_file() and path.suffix in {".json", ".sarif"}:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                path.write_text(json.dumps(redact(value), indent=2) + "\n", encoding="utf-8")
            except (ValueError, UnicodeError):
                # Partial scanner output is neither valid evidence nor safe to publish.
                path.unlink()


if __name__ == "__main__":
    main()
