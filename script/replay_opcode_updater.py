from struct import *
import sys,os
file = sys.argv[1]
fd=open(file,"rb")
magicNumber = fd.read(12)
if(magicNumber!=b'FFXIVREPLAY\x00'):
    print("Is not FFXIVREPLAY file")
    exit(0)

def unpack_filedata(typechar,offset=0):
    if(offset):fd.seek(offset)
    raw = fd.read(calcsize(typechar))
    return unpack(typechar, raw)[0]

def unpack_filedatas(typechar,offset=0):
    if(offset):fd.seek(offset)
    raw = fd.read(calcsize(typechar))
    return unpack(typechar, raw)

replayVersion=unpack_filedata('i', 0x10)
replayLength=unpack_filedata('i', 0x48)+0x364
print(f"replayVersion: 0x{replayVersion:x}")
print(f"replayLength:  0x{replayLength:x}({replayLength})")

fd.seek(0)
fw=open(file.split(".dat")[0]+"_new.dat","ab+")
fw.write(fd.read(0x364))

def parse_recordpacket(offset=0):
    if(offset):fd.seek(offset)
    opcode,dataLength,ms,objectID=unpack_filedatas('H H I I')
    
    newopcode=newop(opcode)
    print(f"{opcode:x}=>{newopcode:x}|{dataLength:x}|{ms:x}|{objectID:x}")

    fw.write(pack('H H I I', newopcode,dataLength,ms,objectID))
    fw.write(fd.read(dataLength))


new={
	"0": ["1406dd3d6", "187", "278", "PlayerSpawn"],
	"1": ["1406dd406", "391", "280", "NpcSpawn"],
	"2": ["1406dd436", "225", "3F0", "NpcSpawn2"],
	"3": ["1406dd466", "1C3", "8", "ActorFreeSpawn"],
	"4": ["1406dd496", "11A", "40", "ObjectSpawn"],
	"5": ["1406dd4c6", "A4", "8", "ObjectDespawn"],
	"6": ["1406dd4f6", "99", "70", "CreateTreasure"],
	"7": ["1406dd526", "2E1", "18", "OpenTreasure"],
	"8": ["1406dd556", "2A7", "8", "TreasureFadeOut"],
	"9": ["1406dd586", "2A1", "10", "ActorMove"],
	"10": ["1406dd5b6", "286", "8", "_record_unk10_"],
	"11": ["1406dd5e6", "394", "10", "Transfer"],
	"12": ["1406dd616", "3C1", "78", "Effect"],
	"13": ["1406dd646", "78", "278", "AoeEffect8"],
	"14": ["1406dd676", "398", "4B8", "AoeEffect16"],
	"15": ["1406dd6a6", "2EA", "6F8", "AoeEffect32"],
	"16": ["1406dd6d6", "210", "938", "AoeEffect64"],
	"17": ["1406dd706", "207", "20", "ActorCast"],
	"18": ["1406dd75b", "363", "18", "ActorControl"],
	"19": ["1406dd7bb", "1EC", "20", "ActorControlTarget"],
	"20": ["1406dd854", "267", "20", "ActorControlSelf"],
	"21": ["1406dda36", "126", "18", "DirectorVars"],
	"22": ["1406dda66", "247", "88", "ContentDirectorSync"],
	"23": ["1406dda96", "27B", "108", "_record_unk23_"],
	"24": ["1406ddac6", "2D9", "10", "EnvironmentControl"],
	"25": ["1406ddaf6", "3E4", "18", "_record_unk25_"],
	"26": ["1406ddb26", "138", "30", "_record_unk26_"],
	"27": ["1406ddb56", "35E", "40", "_record_unk27_"],
	"28": ["1406ddb86", "C9", "18", "_record_unk28_"],
	"29": ["1406ddbb6", "341", "8", "_record_unk29_"],
	"30": ["1406ddbe6", "2AF", "20", "LandSetMap"],
	"31": ["1406ddc16", "178", "A0", "_record_unk31_"],
	"32": ["1406ddc46", "213", "260", "_record_unk32_"],
	"33": ["1406ddc76", "1CF", "4C0", "_record_unk33_"],
	"34": ["1406ddcb2", "1C5", "18", "EventStart"],
	"35": ["1406ddd2b", "B6", "10", "EventFinish"],
	"36": ["1406dddbf", "269", "40", "EventPlay8"],
	"37": ["1406dddd2", "23A", "418", "EventPlay255"],
	"38": ["1406ddde5", "1F5", "28", "EventPlay"],
	"39": ["1406dddf8", "73", "220", "EventPlay128"],
	"40": ["1406dde0b", "278", "60", "EventPlay16"],
	"41": ["1406dde36", "36b", "A0", "EventPlay32"],
	"42": ["1406dde49", "357", "30", "EventPlay4"],
	"43": ["1406dde5c", "288", "120", "EventPlay64"],
	"44": ["1406dde99", "384", "40", "BattleTalk8"],
	"45": ["1406ddeac", "20F", "30", "BattleTalk4"],
	"46": ["1406ddebf", "192", "28", "BattleTalk2"],
	"47": ["1406ddef9", "368", "38", "BalloonTalk4"],
	"48": ["1406ddf0c", "117", "30", "BalloonTalk2"],
	"49": ["1406ddf1f", "CD", "48", "BalloonTalk8"],
	"50": ["1406ddf6b", "29C", "30", "SystemLogMessage48"],
	"51": ["1406ddf7e", "208", "20", "SystemLogMessage32"],
	"52": ["1406ddf91", "174", "18", "SystemLogMessage"],
	"53": ["1406ddfa4", "C7", "90", "SystemLogMessage144"],
	"54": ["1406ddfb7", "95", "50", "SystemLogMessage80"],
	"55": ["1406ddfe6", "324", "20", "NpcYell"],
	"56": ["1406de016", "186", "18", "ActorSetPos"],
	"57": ["1406de046", "1D7", "10", "PrepareZoning"],
	"58": ["1406de076", "1B2", "18", "_record_unk58_"],
	"59": ["1406de0a6", "24D", "168", "StatusEffectList3"],
	"60": ["1406de0d6", "163", "8", "WeatherChange"],
	"61": ["1406de112", "211", "DD8", "UpdateParty"],
	"62": ["1406de1a6", "183", "348", "UpdateAlliance"],
	"63": ["1406de1d6", "3B9", "418", "UpdateLightParty"],
	"64": ["1406de206", "10D", "8", "UpdateHpMpTp"],
	"65": ["1406de236", "2A4", "180", "StatusEffectList"],
	"66": ["1406de266", "1DE", "180", "EurekaStatusEffectList"],
	"67": ["1406de296", "9C", "180", "StatusEffectList2"],
	"68": ["1406de2c6", "A6", "2E8", "BossStatusEffectList"],
	"69": ["1406de30f", "36C", "60", "EffectResult"],
	"70": ["1406de322", "16F", "168", "EffectResult4"],
	"71": ["1406de335", "123", "2C8", "EffectResult8"],
	"72": ["1406de348", "EA", "588", "EffectResult16"],
	"73": ["1406de394", "1CC", "88", "EffectResultBasic8"],
	"74": ["1406de3a7", "197", "108", "EffectResultBasic16"],
	"75": ["1406de3ba", "8B", "408", "EffectResultBasic64"],
	"76": ["1406de3cd", "1ED", "208", "EffectResultBasic32"],
	"77": ["1406de3f2", "2E9", "18", "EffectResultBasic"],
	"78": ["1406de405", "261", "48", "EffectResultBasic4"],
	"79": ["1406de436", "BF", "40", "PartyPos"],
	"80": ["1406de466", "A2", "80", "AlliancePos"],
	"81": ["1406de496", "36F", "A0", "LightPartyPos"],
	"82": ["1406de4c6", "15D", "70", "PlaceMarker"],
	"83": ["1406de4f6", "223", "68", "PlaceFieldMarkerPreset"],
	"84": ["1406de526", "175", "10", "PlaceFieldMarker"],
	"85": ["1406de556", "A9", "10", "ActorGauge"],
	"86": ["1406de586", "180", "8", "CharaVisualEffect"],
	"87": ["1406de5b6", "366", "18", "Fall"],
	"88": ["1406de5e6", "250", "48", "UpdateHate"],
	"89": ["1406de616", "359", "108", "UpdateHater"],
	"90": ["1406de646", "25A", "10", "FirstAttack"],
	"91": ["1406de676", "212", "40", "ModelEquip"],
	"92": ["1406de6a6", "1BF", "8", "EquipDisplayFlags"],
	"93": ["1406de6d6", "87", "78", "_record_unk93"],
	"94": ["1406de706", "1C2", "10", "_record_unk94"],
	"95": ["1406de736", "22C", "40", "_record_unk95"],
	"96": ["1406de766", "FE", "280", "_record_unk96"],
	"97": ["1406de796", "329", "310", "_record_unk97"],
	"98": ["1406de7c6", "399", "4C0", "_record_unk98"],
	"99": ["1406de7f6", "39D", "28", "_record_unk99"],
	"100": ["1406de826", "1E0", "8", "_record_unk100"],
	"101": ["1406de856", "284", "8", "_record_unk101"],
	"102": ["1406de886", "236", "20", "_record_unk102"],
	"103": ["1406de8b6", "3D0", "58", "_record_unk103"],
	"104": ["1406de8e6", "21C", "50", "_record_unk104"],
	"105": ["1406de916", "2B8", "20", "_record_unk105"],
	"106": ["1406de946", "1B6", "128", "_record_unk106"],
	"107": ["1406de976", "301", "C30", "_record_unk107"],
	"108": ["1406de9a6", "39B", "50", "_record_unk108"],
	"109": ["1406de9d6", "1CB", "20", "_record_unk109"],
	"110": ["1406dea06", "116", "C0", "_record_unk110"],
	"111": ["1406dea36", "25B", "10", "_record_unk111"],
	"112": ["1406dea66", "294", "10", "UnMount"],
	"113": ["1406dea96", "16B", "10", "Mount"],
	"114": ["1406deac6", "3E2", "40", "PlayMotionSync"],
	"115": ["1406deafb", "1FF", "30", "CountdownInitiate"],
	"116": ["1406deb36", "140", "28", "CountdownCancel"],
	"117": ["1406df2b2", "94", "68", "InitZone"]
}
old={
	"": ["1406dd4a6", "7F", "278", "PlayerSpawn"],
	"1": ["1406dd4d6", "39E", "280", "NpcSpawn"],
	"2": ["1406dd506", "2E5", "3F0", "NpcSpawn2"],
	"3": ["1406dd536", "28A", "8", "ActorFreeSpawn"],
	"4": ["1406dd566", "31B", "40", "ObjectSpawn"],
	"5": ["1406dd596", "1B3", "8", "ObjectDespawn"],
	"6": ["1406dd5c6", "3BE", "70", "CreateTreasure"],
	"7": ["1406dd5f6", "A1", "18", "OpenTreasure"],
	"8": ["1406dd626", "2B2", "8", "TreasureFadeOut"],
	"9": ["1406dd656", "1DB", "10", "ActorMove"],
	"10": ["1406dd686", "3D3", "8", "_record_unk10_"],
	"11": ["1406dd6b6", "2F8", "10", "Transfer"],
	"12": ["1406dd6e6", "1C9", "78", "Effect"],
	"13": ["1406dd716", "24A", "278", "AoeEffect8"],
	"14": ["1406dd746", "38A", "4B8", "AoeEffect16"],
	"15": ["1406dd776", "C8", "6F8", "AoeEffect32"],
	"16": ["1406dd7a6", "32B", "938", "AoeEffect64"],
	"17": ["1406dd7d6", "29C", "20", "ActorCast"],
	"18": ["1406dd82b", "179", "18", "ActorControl"],
	"19": ["1406dd88b", "220", "20", "ActorControlTarget"],
	"20": ["1406dd924", "26F", "20", "ActorControlSelf"],
	"21": ["1406ddb06", "27B", "18", "DirectorVars"],
	"22": ["1406ddb36", "208", "88", "ContentDirectorSync"],
	"23": ["1406ddb66", "3C1", "108", "_record_unk23_"],
	"24": ["1406ddb96", "2CE", "10", "EnvironmentControl"],
	"25": ["1406ddbc6", "181", "18", "_record_unk25_"],
	"26": ["1406ddbf6", "239", "30", "_record_unk26_"],
	"27": ["1406ddc26", "1C2", "40", "_record_unk27_"],
	"28": ["1406ddc56", "CC", "18", "_record_unk28_"],
	"29": ["1406ddc86", "185", "8", "_record_unk29_"],
	"30": ["1406ddcb6", "BC", "20", "LandSetMap"],
	"31": ["1406ddce6", "D3", "A0", "_record_unk31_"],
	"32": ["1406ddd16", "2E4", "260", "_record_unk32_"],
	"33": ["1406ddd46", "100", "4C0", "_record_unk33_"],
	"34": ["1406ddd82", "1A1", "18", "EventStart"],
	"35": ["1406dddfb", "194", "10", "EventFinish"],
	"36": ["1406dde8f", "1CD", "60", "EventPlay16"],
	"37": ["1406ddea2", "1D2", "418", "EventPlay255"],
	"38": ["1406ddeb5", "2DE", "40", "EventPlay8"],
	"39": ["1406ddec8", "337", "120", "EventPlay64"],
	"40": ["1406ddedb", "1FE", "28", "EventPlay"],
	"41": ["1406ddf03", "2FC", "220", "EventPlay128"],
	"42": ["1406ddf16", "317", "30", "EventPlay4"],
	"43": ["1406ddf29", "7C", "A0", "EventPlay32"],
	"44": ["1406ddf66", "29E", "30", "BattleTalk8"],
	"45": ["1406ddf79", "1A9", "28", "BattleTalk2"],
	"46": ["1406ddf8c", "B2", "40", "BattleTalk4"],
	"47": ["1406ddfc6", "3AD", "38", "BalloonTalk4"],
	"48": ["1406ddfd9", "23E", "30", "BalloonTalk2"],
	"49": ["1406ddfec", "93", "48", "BalloonTalk8"],
	"50": ["1406de038", "279", "90", "SystemLogMessage144"],
	"51": ["1406de04b", "18B", "30", "SystemLogMessage48"],
	"52": ["1406de05e", "16F", "20", "SystemLogMessage32"],
	"53": ["1406de071", "ED", "50", "SystemLogMessage80"],
	"54": ["1406de084", "9A", "18", "SystemLogMessage"],
	"55": ["1406de0b6", "35A", "20", "NpcYell"],
	"56": ["1406de0e6", "18C", "18", "ActorSetPos"],
	"57": ["1406de116", "195", "10", "PrepareZoning"],
	"58": ["1406de146", "301", "18", "_record_unk58_"],
	"59": ["1406de176", "24C", "168", "StatusEffectList3"],
	"60": ["1406de1a6", "C7", "8", "WeatherChange"],
	"61": ["1406de1e2", "1F6", "DD8", "UpdateParty"],
	"62": ["1406de276", "12C", "348", "UpdateAlliance"],
	"63": ["1406de2a6", "33E", "418", "UpdateLightParty"],
	"64": ["1406de2d6", "383", "8", "UpdateHpMpTp"],
	"65": ["1406de306", "2BC", "180", "StatusEffectList"],
	"66": ["1406de336", "353", "180", "EurekaStatusEffectList"],
	"67": ["1406de366", "164", "180", "StatusEffectList2"],
	"68": ["1406de396", "1EE", "2E8", "BossStatusEffectList"],
	"69": ["1406de3dc", "250", "588", "EffectResult16"],
	"70": ["1406de3ef", "22C", "60", "EffectResult"],
	"71": ["1406de402", "1B6", "168", "EffectResult4"],
	"72": ["1406de415", "16E", "2C8", "EffectResult8"],
	"73": ["1406de467", "275", "408", "EffectResultBasic64"],
	"74": ["1406de47a", "1D7", "88", "EffectResultBasic8"],
	"75": ["1406de48d", "121", "48", "EffectResultBasic4"],
	"76": ["1406de4a0", "332", "208", "EffectResultBasic32"],
	"77": ["1406de4c2", "3D9", "108", "EffectResultBasic16"],
	"78": ["1406de4d5", "384", "18", "EffectResultBasic"],
	"79": ["1406de506", "2CB", "40", "PartyPos"],
	"80": ["1406de536", "37C", "80", "AlliancePos"],
	"81": ["1406de566", "10C", "A0", "LightPartyPos"],
	"82": ["1406de596", "34E", "70", "PlaceMarker"],
	"83": ["1406de5c6", "204", "68", "PlaceFieldMarkerPreset"],
	"84": ["1406de5f6", "38E", "10", "PlaceFieldMarker"],
	"85": ["1406de626", "171", "10", "ActorGauge"],
	"86": ["1406de656", "1E9", "8", "CharaVisualEffect"],
	"87": ["1406de686", "336", "18", "Fall"],
	"88": ["1406de6b6", "134", "48", "UpdateHate"],
	"89": ["1406de6e6", "2F9", "108", "UpdateHater"],
	"90": ["1406de716", "1D3", "10", "FirstAttack"],
	"91": ["1406de746", "286", "40", "ModelEquip"],
	"92": ["1406de776", "303", "8", "EquipDisplayFlags"],
	"93": ["1406de7a6", "8C", "78", "_record_unk93"],
	"94": ["1406de7d6", "79", "10", "_record_unk94"],
	"95": ["1406de806", "300", "40", "_record_unk95"],
	"96": ["1406de836", "12F", "280", "_record_unk96"],
	"97": ["1406de862", "310", "r8", "_record_unk97"],
	"98": ["1406de896", "2ED", "4C0", "_record_unk98"],
	"99": ["1406de8c6", "1DA", "28", "_record_unk99"],
	"100": ["1406de8f6", "189", "8", "_record_unk100"],
	"101": ["1406de926", "7B", "8", "_record_unk101"],
	"102": ["1406de956", "BE", "20", "_record_unk102"],
	"103": ["1406de986", "1D1", "58", "_record_unk103"],
	"104": ["1406de9b6", "341", "50", "_record_unk104"],
	"105": ["1406de9e6", "120", "20", "_record_unk105"],
	"106": ["1406dea16", "99", "128", "_record_unk106"],
	"107": ["1406dea46", "EB", "C30", "_record_unk107"],
	"108": ["1406dea76", "6B", "50", "_record_unk108"],
	"109": ["1406deaa6", "29B", "20", "_record_unk109"],
	"110": ["1406dead6", "351", "C0", "_record_unk110"],
	"111": ["1406deb06", "191", "10", "_record_unk111"],
	"112": ["1406deb36", "3A7", "10", "UnMount"],
	"113": ["1406deb66", "322", "10", "Mount"],
	"114": ["1406deb96", "25B", "40", "PlayMotionSync"],
	"115": ["1406debcb", "3B1", "30", "CountdownInitiate"],
	"116": ["1406dec06", "B6", "28", "CountdownCancel"],
	"117": ["1406df382", "222", "68", "InitZone"]
}
def _opcode2name(l):
    return {l[k][1]:l[k][3] for k in l}
def _name2opcode(l):
    return {l[k][3]:l[k][1] for k in l}
name2opcode=_name2opcode(new)
opcode2name=_opcode2name(old)
newop = lambda op: int(name2opcode[opcode2name[f"{op:X}"]],16)

while(fd.tell()<replayLength):
    parse_recordpacket()

fd.close()
fw.close()