#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

import idapro


DEFAULT_TARGET = r"E:\Projects\FFXIVNETOP\FFXIV_BIN\ffxiv_dx11_7.51.exe"
DEFAULT_SCRIPT = Path(__file__).with_name("ffxiv_opcode_finder.py")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run ffxiv_opcode_finder.py through IDA Pro idalib."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=DEFAULT_TARGET,
        help="Target executable or existing IDB/I64 database.",
    )
    parser.add_argument(
        "-s",
        "--script",
        default=str(DEFAULT_SCRIPT),
        help="IDAPython script to execute after auto-analysis.",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Close the database without saving changes.",
    )
    parser.add_argument(
        "--args",
        default=None,
        help="Optional IDA open_database command-line arguments.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = Path(args.target).resolve()
    script = Path(args.script).resolve()

    if not target.is_file():
        print(f"Target does not exist: {target}", file=sys.stderr)
        return 2
    if not script.is_file():
        print(f"IDAPython script does not exist: {script}", file=sys.stderr)
        return 2

    # Import IDA modules only after importing idapro first.
    import ida_auto
    import ida_idaapi

    print(f"IDA library version: {idapro.get_library_version()}")
    print(f"Opening database: {target}")
    rc = idapro.open_database(str(target), True, args=args.args)
    if rc != 0:
        print(f"open_database returned non-zero status: {rc}", file=sys.stderr)
        return rc

    try:
        print("Waiting for auto-analysis...")
        ida_auto.auto_wait()

        print(f"Executing IDAPython script: {script}")
        ida_idaapi.IDAPython_ExecScript(str(script), globals())

        print("Finder script completed.")
        return 0
    finally:
        save = not args.no_save
        print(f"Closing database (save={save})...")
        idapro.close_database(save)


if __name__ == "__main__":
    raise SystemExit(main())
