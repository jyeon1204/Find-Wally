# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import os
import threading
import time
from xml.etree import ElementTree as ET
from datetime import datetime as DT
from xml.etree.ElementTree import Element, dump, parse, SubElement, ElementTree, tostring
from xml.dom import minidom
import xml.etree.cElementTree as CET
import codecs

now_time = DT.today().strftime("%Y-%m-%d")
print(now_time)
xml_name = now_time + '.xml'


def get_event_to_xml():  # 초기 Event를 xml 로 생성해주는 함수 / 부팅시 호출 요망
    print("Get Event to xmls....")
    os.system(f"wevtutil.exe qe \"Microsoft-Windows-Windows Defender/Operational\"  /q:\"*[System[EventID = 1116]]\" /f:xml > {xml_name}")
    print("Create xml file done")
    with open(xml_name) as f:
       make_xml_root_tag(f.readlines())
    #  threading.Timer(5, get_xml).start()


def get_event_xml_lines():  # 현재 생성된 xml 파일을 Line 으로 불러와 root tag 를 제거한 뒤 list 형태로 반환
    with open(xml_name, 'r') as f:
        xml_lines = f.readlines()
    for i in range(0, 2):
        del xml_lines[0]
        if i == 1:
            del xml_lines[-1]
    return xml_lines


def get_last_event_date():  # 마지막 Event 날짜 및 시간을 반환하는 함수
    last_event_xml = get_event_xml_lines()
    last_event_xml = last_event_xml[-1]  # xml 라인을 불러온 뒤 마지막줄 저장

    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    last_event_xml = ET.fromstring(last_event_xml)
    date_tmp = last_event_xml.findall(".//ns:TimeCreated", ns)
    last_event_date = date_tmp[0].attrib
    return last_event_date['SystemTime']


def get_new_event_xml_lines():  # 마지막 Event 시간후의 이벤트 수집 후 list 형태로 반환
    tmp_file = 'tmp.xml'
    last_event_time = get_last_event_date()
    print(f"last event time = {last_event_time}")
    os.system(f'wevtutil.exe qe "Microsoft-Windows-Windows Defender/Operational"  /q:"*[System[EventID = 1116]]" /f:xml > C:\test.xml')
    with open(tmp_file) as f:
        new_xml_lines = f.readlines()
    os.remove(tmp_file)
    return new_xml_lines


def make_xml_root_tag(list_xml):  # list를 넣으면 최종적으로 root tag 생성 후 파일 생성
    # list_xml = get_event_xml_lines()
    os.system(f"echo ^<?xml version=\"1.0\" encoding=\"euc-kr\"?^>> {xml_name}")
    os.system(f"echo ^<Events^>>> {xml_name}")
    with open(xml_name, 'a') as f:
        f.writelines(list_xml)
    os.system(f"echo ^</Events^>>> {xml_name}")


def make_xml_file():  # xml 없으면 생성하고 있으면 현재시간 까지 추가
    if os.path.isfile(xml_name):
        final_xml_lines = get_event_xml_lines() + get_new_event_xml_lines()
        make_xml_root_tag(final_xml_lines)
    elif not os.path.isfile(xml_name):
        get_event_to_xml()


def click_detection():  # 탐지를 누르게되면 호출될 함수 위의 함수와 동일
    make_xml_file()


get_event_to_xml()
#get_event_xml_lines()
#get_last_event_date()
#event_collecter()
#make_xml_root_tag()
#make_xml_file()

namespace = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
utfparser = CET.XMLParser(encoding='ISO-8859-1')
targetTree = CET.parse(xml_name, parser=utfparser)
pageIds = targetTree.find(".//ns:EventID", namespace)
print("EventId:", pageIds.text)
