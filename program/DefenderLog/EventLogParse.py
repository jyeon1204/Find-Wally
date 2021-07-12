import xml.etree.ElementTree as elemTree
from program.DefenderLog.ParseLog import xml_name
#from xml import etree
#from xml.etree.ElementTree import ElementTree
import pandas as pd

parser = elemTree.XMLParser(encoding="ISO-8859-1")
tree = elemTree.parse(xml_name, parser=parser)# 최상단 루트 태그 설정
root = tree.getroot()

ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
#xtree = elemTree.fromstring(tree)
Data = tree.find(".//ns:Data", ns)
#필요없는 부분
# print(Data.tag)  # tag name -> Data
# print(Data.attrib)  # {'name' : 'Product Name'}
# print(Data.get('Name'))  # attr value -> Product Name (속성값 이름)
rows = []
columns = ["Product Name", "Detection time", "Treat Name", "Threat ID", "Severity Name", "Severity ID", "Category Name", "Detection User","Path","Origin Name","Type Name" ]

for child in root:
    # Data.text는 Data 캡션 안에 있는 데이터를 추출해서 출력 -> <Data>여기!</Data>
    #print(Data.text)  # Windows Defender 바이러스 백신
    Data2 = child.find(".//ns:Data[@Name='Detection Time']", ns)  # Name 속성값에 맞는 text 값 찾아오기
    #print(Data2.text)  # 2020-11-10T00:06:26.958Z
    Data3 = child.find(".//ns:Data[@Name='Threat Name']", ns)  # Name 속성값에 맞는 text 값 찾아오기
    #print(Data3.text)  # Virus:Win32/MpTest!amsi
    Data4 = child.find(".//ns:Data[@Name='Threat ID']", ns)  # Name 속성값에 맞는 text 값 찾아오기
    #print(Data4.text)  # = 2147694217(ID)
    Data5 = child.find(".//ns:Data[@Name='Severity Name']", ns)  # Name 속성값에 맞는 text 값 찾아오기
    #print(Data5.text)  # = 2147694217(ID)
    Data6 = child.find(".//ns:Data[@Name='Severity ID']", ns)  # Name 속성값에 맞는 text 값 찾아오기
    #print(Data6.text)
    Data7 = child.find(".//ns:Data[@Name='Category Name']", ns)  # Name 속성값에 맞는 text 값 찾아오기
    #print(Data7.text)  # = 2147694217(ID)
    Data8 = child.find(".//ns:Data[@Name='Detection User']", ns)  # Name 속성값에 맞는 text 값 찾아오기
    #print(Data8.text)  # = 2147694217(ID)
    Data9 = child.find(".//ns:Data[@Name='Path']", ns)  # Name 속성값에 맞는 text 값 찾아오기
    #print(Data9.text)  # = 2147694217(ID)
    Data10 = child.find(".//ns:Data[@Name='Origin Name']", ns)  # Name 속성값에 맞는 text 값 찾아오기
    #print(Data10.text)  # = 2147694217(ID)
    Data11 = child.find(".//ns:Data[@Name='Type Name']", ns)  # Name 속성값에 맞는 text 값 찾아오기
    #print(Data11.text)  # = 2147694217(ID)
    #print("\n")
    rows.append({"Product Name":Data.text,
                 "Detection time":Data2.text,
                 "Treat Name":Data3.text,
                 "Threat ID":Data4.text,
                 "Severity Name": Data5.text,
                 "Severity ID": Data6.text,
                 "Category Name": Data7.text,
                 "Detection User": Data8.text,
                 "Path": Data9.text,
                 "Origin Name": Data10.text,
                 "Type Name": Data11.text
                 })

catalog_cd_df = pd.DataFrame(rows, columns= columns)
#print(catalog_cd_df)

#print(type(catalog_cd_df.loc[len(catalog_cd_df)-1]['Severity ID']))
#print(len(catalog_cd_df))

# 지금은 제일 첫 번째 단일 이벤트만 가져왔지만, 배열을 통해 제일 최근 이벤트 부터 30개의 이벤트를 배열에 넣어야함!!
# 배열에 받은 데이터를 GUI 화면으로 넘겨서, 이를 List 형식으로 출력할 예정