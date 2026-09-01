from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    template = args.template.read_text(encoding="utf-8")
    if template.count("__COMMONS_DATA__") != 1:
        raise SystemExit("Template must contain exactly one __COMMONS_DATA__ placeholder")
    data = args.data.read_text(encoding="utf-8").replace("</", "<\\/")
    result = template.replace("__COMMONS_DATA__", data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(result, encoding="utf-8", newline="\n")
    print(f"{args.output}\t{args.output.stat().st_size} bytes")


if __name__ == "__main__":
    main()
