import idautils

from pathlib import Path,PurePath

def FixedPath(path='',suffix='')-> Path:
    return Path(PurePath(__file__).parent,path).with_suffix(suffix)
#TODO
#idautils.DecodeInstruction(0x140A3E664)