from ffdraw_pkt import FFdrawDumpWriter
from replay_pkt import ReplayRecordReader
from lib.delta import DeltaBox
from lib.opcodes import OpcodesLoader


import argparse,pathlib
from struct import unpack

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output',type=pathlib.Path,required=False)
    parser.add_argument('-i', '--input',type=pathlib.Path,required=True)
    args = parser.parse_args()
    assert args.input.exists(), "Invaild Replay.dat Path"
    if args.output==None:args.output=args.input.with_suffix(".dmp")
    
    replay_pkt=ReplayRecordReader(args.input)
    
    opcoder=OpcodesLoader()
    opcodes=opcoder.op_record(replay_pkt.game_version)
    delta=DeltaBox(replay_pkt.game_version)
    initzone=opcodes.name('InitZone').opcode

    ffdraw_pkt=FFdrawDumpWriter(args.output,replay_pkt.game_version,replay_pkt.start_log_time)
    fixvalue=0
    for header,data in replay_pkt:
        if header.opcode==initzone:
            k1,k2=unpack("BB",data[0x15:0x15+2])
            k3=unpack("I",data[0x18:0x18+4])[0]
            if k1!=0:
                fixvalue=delta.calc_add_value(k1,k2,k3)
                print(f"{k1:x} {k2:x} {k3:08x} -> {fixvalue:x}")
            else:
                fixvalue=0
        ffdraw_pkt.write(header.timestamp_ms,True,False,header.opcode,header.object_id,data,fixvalue)