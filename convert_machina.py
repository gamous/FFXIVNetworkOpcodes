from dataclasses import replace
import os, json, re

isCN = True
opcodefile = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), f"opcodes{'_cn'if isCN else ''}.json"
)
templatefile = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), f"machina.template"
)
resultfile = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), f"machina{'_cn'if isCN else ''}.txt"
)
opcodes = {}
mtemplate = []
result = []
with open(opcodefile, "r") as f:
    opcodes = json.load(f)
opcode_all = (
    opcodes["lists"]["ServerZoneIpcType"] + opcodes["lists"]["ClientZoneIpcType"]
)
with open(templatefile, "r") as f:
    mtemplate = f.readlines()
for l in mtemplate:
    opcode_temp = re.match(r".+(?P<opcode_name>\{.+\})", l).groupdict()["opcode_name"]
    opcode_name = opcode_temp[1:-1]
    for op in opcode_all:
        if op["name"] == opcode_name:
            l = l.replace(opcode_temp, f"{op['opcode']:X}")
            break
    result.append(l)
with open(resultfile, "w+") as f:
    f.writelines(result)
