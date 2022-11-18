# FFXIVNetworkOpcodes

## ffxiv_opcode_finder.py

This support **Python3** and **IDA7** only.

Press `Alt+F7` and Select this script

then everything is ok.

No need to set anything up !

Welcom to contribute the signatures in [signatures.json](https://github.com/gamous/FFXIVNetworkOpcode/blob/main/signatures.json).

Some mapping of synonyms provided in [NAME.md](https://github.com/gamous/FFXIVNetworkOpcode/blob/main/NAME.md)



#### Supported IpcType

- In JmpTable Switch with certain case in path
- In simple Switch with variable parameter call
- Any call to send ZonePacket



#### Todo

- More generators
- Support more complex but not jmptable switch



#### Related Work

[karashiiro/FFXIVOpcodes](https://github.com/karashiiro/FFXIVOpcodes)

[zhyupe/ffxiv-opcode-worker](https://github.com/zhyupe/ffxiv-opcode-worker)

[NukoOoOoOoO/FFXIV-OpcoeFinder](https://github.com/NukoOoOoOoO/FFXIV-OpcoeFinder)
