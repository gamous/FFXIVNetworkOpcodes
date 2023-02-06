# FFXIVNetworkOpcodes

## ffxiv_opcode_finder.py

**Python3** and **IDA7** are required.

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

## record_opcode_finder.py

**Python3** and **IDA7** are required.

Run after `ffxiv_opcode_finder.py`

It will find all opcodes which in-game duty recorder would  recorded, 

which means all opcodes about content director included in.

However we still need some manual works to fixed the output `opcodes_record_raw.json` to `opcodes_record.json`, and then the `replay_updater.py` can use it.

## scripts

### replay_updater.py

**Python3** is required.

```
usage: python replay_updater.py record.dat old_record.json new_record.json <check_name>
example: py .\replay_updater.py '.\2023.01.15 20.03.49.dat' ..\output\Global_2023.01.11\opcodes_record.json ..\output\Global_2023.01.17\opcodes_record.json
```

It uses `opcodes_record.json` to convert your record.dat recorded by in-game recorder between versions and deletes all character identities at the same time to protect your privacy.

#### replay_updater_online.py

Standalone version of replay_updater.py which fetch opcodes file from this repo online

**Python3** and **Httpx** required.

Use `pip install httpx` to install requirement.

```
usage: python replay_updater.py record.dat <check_name>
example: py .\replay_updater.py '.\2023.01.15 20.03.49.dat'
```



## Related Work

[karashiiro/FFXIVOpcodes](https://github.com/karashiiro/FFXIVOpcodes)

[zhyupe/ffxiv-opcode-worker](https://github.com/zhyupe/ffxiv-opcode-worker)

[NukoOoOoOoO/FFXIV-OpcoeFinder](https://github.com/NukoOoOoOoO/FFXIV-OpcoeFinder)

