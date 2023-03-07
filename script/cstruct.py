from ctypes import *

def str_to_ctype(ts:str):
    type_name=ts
    array_size=0
    if(len(ts:=ts.split('*'))>1):
        type_name=ts[0]
        try:
            tz=int(ts[1])
            if(tz>0):array_size=tz
        except:
            pass
    match type_name:
        case "c_char":return c_char if array_size==0 else c_char*array_size
        case "c_int":return c_int if array_size==0 else c_int*array_size
        case "c_uint":return c_uint if array_size==0 else c_uint*array_size
        case "c_int8":return c_int8 if array_size==0 else c_int8*array_size
        case "c_int16":return c_int16 if array_size==0 else c_int16*array_size
        case "c_int32":return c_int32 if array_size==0 else c_int32*array_size
        case "c_int64":return c_int64 if array_size==0 else c_int64*array_size
        case "c_uint8":return c_uint8 if array_size==0 else c_uint8*array_size
        case "c_uint16":return c_uint16 if array_size==0 else c_uint16*array_size
        case "c_uint32":return c_uint32 if array_size==0 else c_uint32*array_size
        case "c_uint64":return c_uint64 if array_size==0 else c_uint64*array_size
        case "c_byte":return c_byte if array_size==0 else c_byte*array_size
        case "c_ubyte":return c_ubyte if array_size==0 else c_ubyte*array_size
        case "c_short":return c_short if array_size==0 else c_short*array_size
        case "c_ushort":return c_ushort if array_size==0 else c_ushort*array_size
        case "c_long":return c_long if array_size==0 else c_long*array_size
        case "c_ulong":return c_ulong if array_size==0 else c_ulong*array_size
        case "c_longlong":return c_longlong if array_size==0 else c_longlong*array_size
        case "c_ulonglong":return c_ulonglong if array_size==0 else c_ulonglong*array_size
        case "c_float":return c_float if array_size==0 else c_float*array_size
        case "c_double":return c_double if array_size==0 else c_double*array_size
        case "c_void_p":return c_void_p if array_size==0 else c_void_p*array_size

def c_struct(cls):
    annotations=cls.__annotations__
    fields=[(field,str_to_ctype(annotations[field])) for field in annotations]
    _pack= 1 if "_pack_" not in dir(cls) else cls._pack_
    class new_cls(Structure):
        _pack_  = _pack    #Pack aligin
        _fields_= fields        #Data format
        def __init__(self, data=None):
            super().__init__()
            if data:self.unpack(data)
        def __bytes__(self) -> bytes:
            return self.pack()
        def __repr__(self) -> str:
            return '<CStruct with fields('+', '.join([f"{i[0]}={getattr(self,i[0])}" for i in self._fields_])+')>'
        def __iter__(self):
            for i in self._fields_:
                yield (i[0],getattr(self,i[0]) )
        def pack(self):
            return string_at(addressof(self),sizeof(self.__class__))
        def unpack(self,raw):
            memmove(addressof(self),raw,sizeof(self.__class__))
            return dict(self)
    for item in set(dir(cls)) - set(dir(new_cls)):
        setattr(new_cls,item,getattr(cls,item))
    return new_cls

