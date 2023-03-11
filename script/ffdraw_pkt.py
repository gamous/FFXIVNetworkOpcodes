from lib.opcodes import *
from lib.ff_pkt_structs import *

from struct import *
import sys,os,json,re,enum,pathlib


class FFdrawDumpReader():
    _ver_ = 0
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

class FFdrawDumpWriter():
    _ver_ = 0
    def __init__(self,file_path,game_version,time) -> None:
        if isinstance(file_path, str): file_path = pathlib.Path(file_path)
        #assert not file_path.parent.exists()
        self.stream=open(file_path,'wb', buffering=0)
        self.game_build_date = game_version
        self.time = time
        self.stream.write(json.dumps(self.get_header(), ensure_ascii=False).encode('utf-8') + b'\n')
    def get_header(self):
        return {
            'dumper_version': self._ver_,
            'game_build_date': self.game_build_date.split('_')[-1]+'.0000.0000',
            'start_log_time': self.time,
        }
    def __del__(self) -> None:
        self.stream.close()
    def write(self, timestamp_ms: int, is_zone: bool, is_up: bool, proto_no: int, source_id: int, data: bytes, fix_value=0):
        to_write = pack(b'BBHIQI',((int(is_zone) << 1) | int(is_up)) , fix_value, proto_no, source_id, timestamp_ms, len(data)) + data
        self.stream.write(to_write)

if __name__=="__main__":
    file_path = sys.argv[1]
    ffd_reader=FFdrawDumpReader(file_path)
    opcodes=ffd_reader.opcoder.op_record(ffd_reader.game_version)
    actor_control_type=ffd_reader.opcoder.actor_control_type()
    print(opcodes.version)
    print(ffd_reader.header)
    input()
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
