from lib.opcodes import *
from lib.ff_pkt_structs import *

from struct import *
import sys,os,json,re,enum,pathlib


class ReplayRecordReader():
    _ver_ = 0
    def __init__(self,file_path) -> None:
        self.stream=open(file_path,"rb")
        magicNumber = self.stream.read(12)
        assert (magicNumber==b'FFXIVREPLAY\x00'), "Is not FFXIVREPLAY file"
        self.replayVersion=self.unpack_filedata('i', 0x10)
        self.replayLength=self.unpack_filedata('i', 0x48)+0x364
        self.start_log_time=self.unpack_filedata('i',0x1C)
        self.delta=0
        self.opcoder=OpcodesLoader()
        self.game_version=self.opcoder.fix_version(self.replayVersion)
        self.start_offset=0x364
        self.stream.seek(self.start_offset)
    def __del__(self) -> None:
        self.stream.close()
    def unpack_filedata(self,typechar,offset=0):
        if(offset):self.stream.seek(offset)
        raw = self.stream.read(calcsize(typechar))
        return unpack(typechar, raw)[0]

    def parse_header(self,header_bytes):
        opcode,size,timestamp_ms,object_id=unpack('HHII',header_bytes)#len=12
        return PacketHeader(opcode,size,timestamp_ms,object_id,0b10)
    def read_next(self):
        if not (header_bytes := self.stream.read(12)): 
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

class ReplayRecordWriter():
    pass

if __name__=="__main__":
    file_path = sys.argv[1]
    replay_reader=ReplayRecordReader(file_path)
    opcodes=replay_reader.opcoder.op_record(replay_reader.game_version)
    actor_control_type=replay_reader.opcoder.actor_control_type()
    print(opcodes.version)
    input()
    start=True
    for header,data in replay_reader:
        if not header.is_zone() or header.is_up() or not opcodes.exist(header.opcode):
            continue
        name=opcodes.o2n(header.opcode)
        print(name)
