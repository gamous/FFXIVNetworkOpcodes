# Mapping of synonyms

Subject to [FFXIVOpcodes](https://github.com/karashiiro/FFXIVOpcodes)' Naming and [ffxiv-opcode-worker/cn-opcodes.csv](https://github.com/zhyupe/ffxiv-opcode-worker/blob/master/cn-opcodes.csv)

## Machina

mappings

```json
{
  "Ability1": "Effect",
  "Ability8": "AoeEffect8",
  "Ability16": "AoeEffect16",
  "Ability24": "AoeEffect24",
  "Ability32": "AoeEffect32",
  "ActorCast": "ActorCast",
  "PresetWaymark": "PlaceFieldMarkerPreset",
  "Waymark": "PlaceFieldMarker"
}
```

txt

```txt
StatusEffectList|{StatusEffectList}
StatusEffectList2|{StatusEffectList2}
StatusEffectList3|{StatusEffectList3}
BossStatusEffectList|{BossStatusEffectList}
Ability1|{Effect}
Ability8|{AoeEffect8}
Ability16|{AoeEffect16}
Ability24|{AoeEffect24}
Ability32|{AoeEffect32}
ActorCast|{ActorCast}
EffectResult|{EffectResult}
EffectResultBasic|{EffectResultBasic}
ActorControl|{ActorControl}
ActorControlSelf|{ActorControlSelf}
ActorControlTarget|{ActorControlTarget}
UpdateHpMpTp|{UpdateHpMpTp}
PlayerSpawn|{PlayerSpawn}
NpcSpawn|{NpcSpawn}
NpcSpawn2|{NpcSpawn2}
ActorMove|{ActorMove}
ActorSetPos|{ActorSetPos}
ActorGauge|{ActorGauge}
PresetWaymark|{PlaceFieldMarkerPreset}
Waymark|{PlaceFieldMarker}
SystemLogMessage|{SystemLogMessage}
```


## XivAlexander

Push to [Soreepeong/XivAlexander/Issues](https://github.com/Soreepeong/XivAlexander/issues)

```json
{
	"C2S_ActionRequest": ActionRequest,
	"C2S_ActionRequestGroundTargeted": ActionRequestGroundTargeted,
	"S2C_ActionEffect01": Effect,
	"S2C_ActionEffect08": AoeEffect8,
	"S2C_ActionEffect16": AoeEffect16,
	"S2C_ActionEffect24": AoeEffect24,
	"S2C_ActionEffect32": AoeEffect32,
	"S2C_ActorCast": ActorCast,
	"S2C_ActorControl": ActorControl,
	"S2C_ActorControlSelf": ActorControlSelf,
	"Server_IpRange": "0.0.0.0/0",
	"Server_PortRange": "1-65535"
}
```

## Others

```json
{
    "InventoryHandlerOffset": "InventoryModifyHandler",
    "MapEffect": "EnvironmentControl"
}
```



## Missing

```
E8 ?? ?? ?? ?? 48 8B D3 48 8B CE E8 ?? ?? ?? ?? 48 8B 9C 24
CurrencyCrystalInfo
ContainerInfo
ItemInfo

E8 ? ? ? ? 48 8B C8 48 85 C0 74 38 66 39 58 78 
DirectorStart
ResultDialog

0F 84 ? ? ? ? 83 FA 20 0F 85 ? ? ? ?
InventoryTransaction
InventoryTransactionFinish

74 6F 3D ? ? ? ? 0F 85 ? ? ? ? 48 8B 59 38
ItemMarketBoardInfo

81 E9 ? ? ? ? 74 7C
RetainerInformation
```

