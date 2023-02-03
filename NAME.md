# Mapping of synonyms

Subject to [FFXIVOpcodes](https://github.com/karashiiro/FFXIVOpcodes)' Naming and [ffxiv-opcode-worker/cn-opcodes.csv](https://github.com/zhyupe/ffxiv-opcode-worker/blob/master/cn-opcodes.csv)

## Sapphire



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



## Dalamud

Push to [ottercorp/DalamudAssets](https://github.com/ottercorp/DalamudAssets)

mappings

```json
{
    "HousingWardInfo": "WardLandInfo",
    "MarketBoardItemRequestStart": "MarketBoardItemListingCount",
    "MarketBoardHistory": "MarketBoardItemListingHistory",
    "MarketBoardOfferings": "MarketBoardItemListing",
    "MarketTaxRates": "ResultDialog",
    "CfNotifyPop": "ContentFinderNotifyPop",
    "AirshipTimers": "CompanyAirshipStatus",
    "SubmarineTimers": "CompanySubmersibleStatus"
}
```

server

```json
{
  "ActorControlSelf": ActorControlSelf,
  "HousingWardInfo": WardLandInfo,
  "ContainerInfo": ContainerInfo,
  "MarketBoardItemRequestStart": MarketBoardItemListingCount,
  "MarketBoardHistory": MarketBoardItemListingHistory,
  "MarketBoardOfferings": MarketBoardItemListing,
  "MarketBoardPurchase": MarketBoardPurchase,
  "InventoryActionAck": InventoryActionAck,
  "MarketTaxRates": ResultDialog,
  "RetainerInformation": RetainerInformation,
  "ItemMarketBoardInfo": ItemMarketBoardInfo,
  "CfNotifyPop": CfNotifyPop,
  "AirshipTimers": CompanyAirshipStatus,
  "SubmarineTimers": CompanySubmersibleStatus
}
```

client

```json
{
  "MarketBoardPurchaseHandler": MarketBoardPurchaseHandler,
  "InventoryModifyHandler": InventoryModifyHandler
}
```



## Bossmod

Push to [Yarukon/ffxiv_bossmod](https://github.com/Yarukon/ffxiv_bossmod/blob/master/BossMod/Framework/Protocol.cs)

mappings

```json
{
    "ActionEffect1": "Effect",
    "ActionEffect8": "AoeEffect8",
    "ActionEffect16": "AoeEffect16",
    "ActionEffect24": "AoeEffect24",
    "ActionEffect32": "AoeEffect32",
    "PresetWaymark": "PlaceFieldMarkerPreset",
    "Waymark": "PlaceFieldMarker",
    "EffectResult1": "EffectResult",
    "EffectResultBasic1": "EffectResultBasic"
}
```

proto

```c#
public enum Opcode
{
    ActionEffect1  = {Effect},
    ActionEffect8  = {AoeEffect8},
    ActionEffect16 = {AoeEffect16},
    ActionEffect24 = {AoeEffect24},
    ActionEffect32 = {AoeEffect32},


    ActorCast      = {ActorCast},
    ActorControl   = {ActorControl},
    ActorControlSelf = {ActorControlSelf},
    ActorControlTarget = {ActorControlTarget},
    ActorGauge = {ActorGauge},

    PresetWaymark = {PlaceFieldMarkerPreset},
    Waymark = {PlaceFieldMarker},

    EffectResult1  = {EffectResult  }, // Size 0x60
    EffectResult4  = {EffectResult4 }, // Size 0x168
    EffectResult8  = {EffectResult8 }, // Size 0x2C8
    EffectResult16 = {EffectResult16}, // Size 0x588

    EffectResultBasic1  = {EffectResultBasic  }, // Size 0x18
    EffectResultBasic4  = {EffectResultBasic4 }, // Size 0x48
    EffectResultBasic8  = {EffectResultBasic8 }, // Size 0x88
    EffectResultBasic16 = {EffectResultBasic16}, // Size 0x108
    EffectResultBasic32 = {EffectResultBasic32}, // Size 0x208
    EffectResultBasic64 = {EffectResultBasic64}, // Size 0x408

    EnvironmentControl = {EnvironmentControl}, 
    UpdateRecastTimes = {UpdateRecastTimes}, // payload = 80 floats 'elapsed' + 80 floats 'total'
    UpdateHate = {UpdateHate}, // payload = byte length + 3 bytes padding + { uint objID, byte enmity, byte padding[3] }[len]
    UpdateHater = {UpdateHater}, // payload = byte length + 3 bytes padding + { uint objID, byte enmity, byte padding[3] }[len]
    RSVData = {RSVData},

    ActionRequest = {ActionRequest}
    ActionRequestGroundTargeted = {ActorControlSelf},
}
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

