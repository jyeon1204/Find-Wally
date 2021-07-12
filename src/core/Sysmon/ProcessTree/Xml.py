import re
import os
import json
import datetime
from lxml import etree as ET
# from ProcessTree.Entry import utc_to_asia_seoul

#xml Parsing

from src.core.Sysmon.ProcessTree.Entry import utc_to_asia_seoul


def parse_xml(filename):
    utf8_parser = ET.XMLParser(encoding='ISO-8859-1',recover=True)
    root = ET.parse(filename,parser=utf8_parser)
    tree = root.getroot()
    xml_children = tree.getchildren()
    return xml_children

def get_time(xml_node):
    time =[]
    for event in xml_node:
        ns = {"ns": event.nsmap[None]}
        route = ".//ns:Data[@Name='UtcTime']"
        utc_time =datetime.datetime.strptime(event.xpath(route,namespaces=ns)[0].text,'%Y-%m-%d %H:%M:%S.%f')
        time.append(utc_time)
        # print(event)
        # print(utc_time)
    return time

# ns = {"ns": event.nsmap[None]}route = ".//ns:Data[@Name='UtcTime']"

def count_timestamp(xml_node):
    time = get_time(xml_node)
    delta = datetime.timedelta(minutes=0.5)
    thirty_sec_timestamps=[]
    time_x = time[0]
    count = 1
    for i in range(1,len(time)):
        print("time{i} : ",time[i])
        if time_x+delta<time[i]:
            tmp = {"name":str(utc_to_asia_seoul(time_x.strftime('%Y-%m-%d %H:%M:%S.%f'))),"count":count}
            thirty_sec_timestamps.append(tmp)
            time_x = time[i]
            count=0
            print("----")
            print(tmp)
        count +=1

    pt = re.compile("[\/:*?\"<>|]", flags = re.VERBOSE)

    ## error point
    time = pt.sub(".",thirty_sec_timestamps[0]['name'])
    path = ".\\detected\\"+time
    try:
        if not os.path.exists(path):
            os.makedirs(path)
    except OSError:
        print('Error: Creating directory' + path)

    with open(path+"\\graph.json","w") as f:
        json.dump(thirty_sec_timestamps,f,indent=2)
    return path