from cstruct import c_struct
from ctypes import *

@c_struct
class ActorControl:
    _size_ = 0X18
    _pack_ = 4
    id:   'c_uint16' #('0X0')
    arg0: 'c_uint32' #('0X4')
    arg1: 'c_uint32' #('0X8')
    arg2: 'c_uint32' #('0XC')
    arg3: 'c_uint32' #('0X10')

@c_struct
class ActorControlSelf:
    _size_ = 0X20
    _pack_ = 4
    id:   'c_uint16' #('0X0')
    arg0: 'c_uint32' #('0X4')
    arg1: 'c_uint32' #('0X8')
    arg2: 'c_uint32' #('0XC')
    arg3: 'c_uint32' #('0X10')
    arg4: 'c_uint32' #('0X14')
    arg5: 'c_uint32' #('0X18')

@c_struct
class ActorControlTarget:
    _size_ = 0X20
    _pack_ = 4
    id:   'c_uint16' #('0X0')
    arg0: 'c_uint32' #('0X4')
    arg1: 'c_uint32' #('0X8')
    arg2: 'c_uint32' #('0XC')
    arg3: 'c_uint32' #('0X10')
    target_id: 'c_uint64' #('0X18')

@c_struct
class ActorCast:
    _size_ = 0X20
    _pack_ = 4
    action_id: 'c_uint16' #('0X0')
    action_kind: 'c_uint8' #('0X2')
    display_delay: 'c_uint8' #('0X3')
    real_action_id: 'c_uint32' #('0X4')
    cast_time: 'c_float' #('0X8')
    target_id: 'c_uint32' #('0XC')
    _facing: 'c_uint16' #('0X10')
    can_interrupt: 'c_uint8' #('0X12')
    _pos: 'c_uint16*3' #('0X18')



a=ActorCast()
a._pos=c_uint16*3
print(a)