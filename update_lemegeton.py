import os

OutputPath = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    f"output",
)

dirs = [entry.split('_') for entry in os.listdir(OutputPath) if not os.path.isfile(os.path.join(OutputPath, entry))]
GL_VER=0
CN_VER=0
KR_VER=0
for d in dirs:
    ver=int(d[1].replace('.',''))
    match d[0]:
        case "Global":
            GL_VER=max(GL_VER,ver)
        case "CN":
            CN_VER=max(CN_VER,ver)
        case "KR":
            KR_VER=max(KR_VER,ver)

GL_VER_NAME=f"Global_{GL_VER//10000:04}.{(GL_VER%10000)//100:02}.{GL_VER%100:02}"
CN_VER_NAME=f"CN_{CN_VER//10000:04}.{(CN_VER%10000)//100:02}.{CN_VER%100:02}"
KR_VER_NAME=f"KR_{KR_VER//10000:04}.{(KR_VER%10000)//100:02}.{KR_VER%100:02}"
print(GL_VER_NAME)
print(CN_VER_NAME)
print(KR_VER_NAME)
GL_path = os.path.join(OutputPath,GL_VER_NAME,"lemegeton.xml")
CN_path = os.path.join(OutputPath,CN_VER_NAME,"lemegeton.xml")
KR_path = os.path.join(OutputPath,KR_VER_NAME,"lemegeton.xml")
with open(GL_path, "r") as f:
    GL_data=f.read()
with open(CN_path, "r") as f:
    CN_data=f.read()
with open(KR_path, "r") as f:
    KR_data=f.read()

ALL_data=f"""<?xml version="1.0" encoding="utf-8"?>
<Blueprint>
	<Regions>
{GL_data}
{CN_data}
{KR_data}
	</Regions>
</Blueprint>
"""
lemegeton_path = os.path.join(OutputPath,"lemegeton.xml")
with open(lemegeton_path, "w+") as f:
    f.write(ALL_data)
print('lemegeton.xml updated')