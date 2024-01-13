from ctypes import *
from functools import reduce

import json,lzma


mul=lambda t,s:t*s
int16=lambda i:int(i,16)

from opcodes import Downloader
class DeltaBox:
    def __init__(self,version,repo_url="file://../output/") -> None:
        self.repo_url=repo_url
        self.downloader=Downloader()
        boxes=self.repo_get_json(f'{version}\delta_box\\box.json')
        sizes1=list(map(int16,boxes["box1"]["size"].split('|')[::-1]))
        sizes2=list(map(int16,boxes["box2"]["size"].split('|')[::-1]))
        sizes3=list(map(int16,boxes["box3"]["size"].split('|')[::-1]))

        self.box1=reduce(mul,sizes1,c_uint32)()
        self.box2=reduce(mul,sizes2,c_uint32)()
        self.box3=reduce(mul,sizes3,c_uint32)()
        self.size1_0=sizes1[0]
        self.size1  =sizes1[1]
        self.size2_0=sizes2[0]
        self.size3_0=sizes3[0]
        self.size3  =sizes3[1]
        if self.repo_url.startswith("file://"):
            with lzma.open(self.repo_url[7:]+f'{version}\delta_box\\box1.bin.lzma','rb') as f:
                f.readinto(self.box1)
            with lzma.open(self.repo_url[7:]+f'{version}\delta_box\\box2.bin.lzma','rb') as f:
                f.readinto(self.box2)
            with lzma.open(self.repo_url[7:]+f'{version}\delta_box\\box3.bin.lzma','rb') as f:
                f.readinto(self.box3)

            #with open(self.repo_url[7:]+f'{version}\delta_box\\box1.bin','rb') as f:
            #    f.readinto(self.box1)
            #with open(self.repo_url[7:]+f'{version}\delta_box\\box2.bin','rb') as f:
            #    f.readinto(self.box2)
            #with open(self.repo_url[7:]+f'{version}\delta_box\\box3.bin','rb') as f:
            #    f.readinto(self.box3)
            #with lzma.open(self.repo_url[7:]+f'{version}\delta_box\\box1.bin.lzma','wb') as f:
            #    f.write(string_at(addressof(self.box3),sizeof(self.box1.__class__)))
            #with lzma.open(self.repo_url[7:]+f'{version}\delta_box\\box2.bin.lzma','wb') as f:
            #    f.write(string_at(addressof(self.box2),sizeof(self.box2.__class__)))
            #with lzma.open(self.repo_url[7:]+f'{version}\delta_box\\box3.bin.lzma','wb') as f:
            #    f.write(string_at(addressof(self.box1),sizeof(self.box3.__class__)))
        else:
            print("todo")
    def repo_get_json(self,rpath:str) -> dict:
        if self.repo_url.startswith("file://"):
            with open(self.repo_url[7:]+rpath,'rb') as fd:
                return json.load(fd)
        else:
            return self.downloader.safe_get(self.repo_url+rpath).json()
    def calc_add_value(self,a1:c_uint8,a2:c_uint8,a3:c_uint)->c_uint8:
        res:c_uint8=  a1
        try:
            res+= 0xff & self.box1[a1 % self.size1][1]
        except:
            print(hex(2 * (a1 % self.size1) + 1))
            exit(0)
        res+= 0xff & self.box2[(3 * (a3 // 0x3C // 0x3C // 0x18) % self.size2_0)]
        res+= 0xff & self.box3[a2 % self.size3][a1 * self.box1[a1 % self.size1][0] % self.size3_0]
        res&= 0xff
        return res

if __name__ == '__main__':
    print(DeltaBox('Global_2023.02.28').calc_add_value(0xd0 ,0x66 ,0x9c107dd1))