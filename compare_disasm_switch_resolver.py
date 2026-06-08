#!/usr/bin/env python3
import os
import sys


REPO_DIR = os.path.dirname(os.path.realpath(__file__))
if REPO_DIR not in sys.path:
    sys.path.insert(0, REPO_DIR)

import ffxiv_opcode_finder as finder


EXPECTED = {
    "EffectResult": [(215, 96), (229, 360), (681, 712), (970, 1416)],
    "EffectResultBasic": [(112, 136), (148, 520), (208, 264), (393, 1032), (425, 72), (596, 24)],
    "EventPlay": [(126, 40), (152, 544), (153, 288), (191, 96), (244, 160), (579, 48), (640, 64), (659, 1048)],
    "EventLogMessage": [(250, 24), (365, 144), (512, 48), (916, 32), (973, 80)],
    "BattleTalk": [(124, 48), (692, 40), (802, 64)],
    "BalloonTalk": [(452, 72), (537, 48), (990, 56)],
}


def fmt_pairs(items):
    return [(item["case"], item["arg"]) for item in sorted(items, key=lambda i: i["case"])]


def main():
    config = finder.ConfigReader()
    init_cfg = config.content["ServerZoneIpcType"]["__init__"]
    failures = 0
    for name, ea in init_cfg.items():
        if name == "ProcessZonePacketDown" or not isinstance(ea, int):
            continue
        resolver = finder.DisasmSwitchResolver(ea)
        actual_pairs = fmt_pairs(resolver.content)
        expected_pairs = EXPECTED[name]
        ok = actual_pairs == expected_pairs
        print(f"{name}: {'OK' if ok else 'DIFF'}")
        print(f"  expected={expected_pairs}")
        print(f"  actual={actual_pairs}")
        if not ok:
            failures += 1
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
