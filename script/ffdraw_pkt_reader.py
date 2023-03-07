import requests

from struct import *
import sys,os,json,re,enum

file_path = sys.argv[1]


class Downloader:
    def __init__(self,retry_times=15) -> None:
        self.retry_times=retry_times
    def safe_get(self,url):
        for _ in range(self.retry_times):
            try:
                return requests.get(url)
            except requests.ConnectTimeout:
                print('Retry Download')
        exit(0)

class RecordOpcodesItem:
    def __init__(self,raw_data)-> None:
        self.address=int(raw_data[0],16)
        self.opcode= int(raw_data[1],16)
        self.size=   int(raw_data[2],16)
        self.name=       raw_data[3]
class RecordOpcodes:
    def __init__(self,raw_data) -> None:
        self.raw_data=raw_data
        self.version=raw_data["version"]
        self.revid=raw_data["ver_id"]
        self.raw_dict=self.raw_data["opcodes"]
        self.code_map={self.raw_dict[i][1]:self.raw_dict[i] for i in self.raw_dict}
        self.name_map={self.raw_dict[i][3]:self.raw_dict[i] for i in self.raw_dict}
    def exist(self,key):
        if isinstance(key,str):
            return key in self.name_map
        if isinstance(key,int):
            return f"{key:03X}" in self.code_map
    def name(self,name):
        if name not in self.name_map:
            return None
        return RecordOpcodesItem(self.name_map[name])
    def opcode(self,opcode):
        if type(opcode) is int:
            opcode=f"{opcode:03X}"
        if opcode not in self.code_map:
            return None
        return RecordOpcodesItem(self.code_map[opcode])
    def name2opcode(self,name):
        if result:=self.name(name):
            return result.opcode
        else:
            return None
    def opcode2name(self,opcode):
        if result:=self.opcode(opcode):
            return result.name
        else:
            return None
    def n2o(self,name):
        return self.name2opcode(name)
    def o2n(self,opcode):
        return self.opcode2name(opcode)

class OpcodesLoader:
    def __init__(self,repo_url="file://../output/") -> None:
        self.repo_url=repo_url
        self.cache=dict()
        self.downloader=Downloader()
        self.meta=self.repo_get("meta.json")
    def repo_get(self,rpath:str) -> dict:
        if rpath not in self.cache:
            if self.repo_url.startswith("file://"):
                with open(self.repo_url[7:]+rpath,'r') as fd:
                    self.cache[rpath]=json.load(fd)
            else:
                self.cache[rpath]=self.downloader.safe_get(self.repo_url+rpath).json()
        return self.cache[rpath]
    def fix_version(self,game_version):
        if re.match(r"^(CN|Global)_\d{4}\.\d{2}\.\d{2}$",game_version):
            return game_version
        if re.match(r"^\d{4}\.\d{2}\.\d{2}.+$",game_version):
            game_build_date=game_version[:10]
            for version in self.meta:
                if version.endswith(game_build_date):
                    return version
        assert f"Invalid GameVersion: {game_version}"
    def op_record(self,game_version) -> RecordOpcodes:
        return RecordOpcodes(self.repo_get(self.fix_version(game_version)+"/opcodes_record.json"))
    def op_internal(self,game_version) -> dict:
        return self.repo_get(self.fix_version(game_version)+"/opcodes_internal.json")

class PacketHeader:
    def __init__(self,opcode,pkt_size,timestamp_ms,object_id,scope) -> None:
        self.opcode=opcode
        self.pkt_size=pkt_size
        self.timestamp_ms=timestamp_ms
        self.object_id=object_id
        self.scope=scope
    def is_zone(self):
        return self.scope & 0b10 > 0
    def is_up(self):
        return self.scope & 0b1 > 0

class FFdrawDumpReader():
    def __init__(self,file_path) -> None:
        self.stream=open(file_path,"rb")
        self.header=json.loads(self.stream.readline().decode('utf-8'))
        self.start_offset=self.stream.tell()
        self.delta=0
        self.opcoder=OpcodesLoader()
        self.game_version=self.opcoder.fix_version(self.header['game_build_date'])
        #dumper_version=0
        #start_log_time
    def __del__(self) -> None:
        self.stream.close()
    def parse_header(self,header_bytes):
        scope, delta, opcode, object_id, timestamp_ms, size = unpack(b'BBHIQI', header_bytes)
        self.delta=delta
        return PacketHeader(opcode,size,timestamp_ms,object_id,scope)
    def read_next(self):
        if not (header_bytes := self.stream.read(20)): 
            return None
        header=self.parse_header(header_bytes)
        data=self.stream.read(header.pkt_size)
        return (header,data)
    def __next__(self):
        if not (result:=self.read_next()):
            raise StopIteration
        return result
    def __iter__(self):
        self.stream.seek(self.start_offset)
        return self

def make_enum(name, values):
    _k = _v = None
    class _enum(enum.Enum):
        nonlocal _k, _v
        for _k, _v in values.items():
            locals()[_k] = _v
    _enum.__name__ = name
    return _enum
def in_enum(key,_enum:enum):
    if isinstance(key,str):
        return key in _enum.__members__
    if isinstance(key,int):
        return key in _enum._value2member_map_

from ff_pkt_structs import *

ffd_reader=FFdrawDumpReader(file_path)
opcodes=ffd_reader.opcoder.op_record(ffd_reader.game_version)
actor_control_type=make_enum("ActorControlType",ffd_reader.opcoder.repo_get("enum.json")["ActorControlType"])
print(opcodes.version)
start=True
for header,data in ffd_reader:
    if not header.is_zone() or header.is_up() or not opcodes.exist(header.opcode):
        continue
    name=opcodes.o2n(header.opcode)
    match name:
        case 'ActorMove':
            continue
        case 'InitZone':
            start=True
        case 'ActorControl':
            data=ActorControl(data)
            print(f'{actor_control_type(data.id) if in_enum(data.id,actor_control_type) else f"AcotrControl(unknown:{data.id})"}')
            if data.id==actor_control_type.DirectorClear:
                start=False
        case 'ActorControlSelf':
            data=ActorControl(data)
            print(f'{actor_control_type(data.id) if in_enum(data.id,actor_control_type) else f"AcotrControl(unknown:{data.id})"}')
            if data.id==actor_control_type.DirectorClear:
                start=False
        case 'ActorControlTarget':
            data=ActorControl(data)
            print(f'{actor_control_type(data.id) if in_enum(data.id,actor_control_type) else f"AcotrControl(unknown:{data.id})"}')
            if data.id==actor_control_type.DirectorClear:
                start=False
        case _:
            if(start):
                print(name)
