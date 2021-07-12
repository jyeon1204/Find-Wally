import os
import subprocess
import sys
import threading
# import schedule  # pip install schedule
from xml.etree import ElementTree as ET
from datetime import datetime as DT
import datetime as DTE
import time
# from ProcessTree.function import abc
from src.core.Sysmon.ProcessTree.function import abc

waiting_min = 30

def get_system_boot_time():  # 부팅시간은 utc+9 이지만 이벤트는 utc 시간에 머물러 있음으로 시간을 9시간 빼주게됨
    test = str(subprocess.check_output('wmic os get lastbootuptime')).split()
    system_boot_time_raw = test[1][6:20]
    #  Event Fonmat 맞게 변형
    system_boot_time = system_boot_time_raw[0:4] + '-' + system_boot_time_raw[4:6] + '-' + system_boot_time_raw[
                                                                                           6:8] + 'T' + system_boot_time_raw[
                                                                                                        8:10] + ':' + system_boot_time_raw[
                                                                                                                      10:12] + ':' + system_boot_time_raw[
                                                                                                                                     12:14]
    convert_time_obj = DT.strptime(system_boot_time, '%Y-%m-%dT%H:%M:%S')
    converted_time = convert_time_obj - DTE.timedelta(hours=9)
    converted_time = converted_time.strftime('%Y-%m-%dT%H:%M:%S')

    system_boot_time = system_boot_time.replace(':', '_')
    return [converted_time, system_boot_time]


event_name = 'Microsoft-Windows-Sysmon/Operational'
boot_time= get_system_boot_time()[1]
xml_name = boot_time + '.xml'  # xml 파일명 'yyyy-mm-dd_hh_mm_ss.xml' 형태
file_name = 'event_tmp.xml'


def get_first_Event_to_xml():
    print("Boot time : ", boot_time)
    print("get event to XML file....")
    os.system(
        f'wevtutil.exe qe \"{event_name}\" /q:\"*[System[TimeCreated[@SystemTime>\'{get_system_boot_time()[0]}\']]]" /e:Events /f:xml > {file_name}')
    print("created dnoe to event XML")


def get_event_30_min():
    print("Last event time : ", get_last_event_date())
    print(f"Get event before {get_last_event_date()} ....")
    last_event_time = get_last_event_date()
    print("Now time : ", DT.now())
    print("Remove old xml...")
    os.remove(file_name)
    os.system(
        f'wevtutil.exe qe "{event_name}"  /q:"*[System[TimeCreated[@SystemTime>\'{last_event_time}\']]]" /e:Events /f:xml > {file_name}')


def get_event_to_xml():  # 초기 Event를 xml 로 생성해주는 함수 부팅시간을 기준으로 이벤트를 가져옴 / 부팅시 호출 요망
    print("Get Event to xmls....")
    boot_time = get_system_boot_time()[0]
    os.system(
        f'wevtutil.exe qe \"{event_name}\" /q:\"*[System[TimeCreated[@SystemTime>\'{boot_time}\']]]" /e:Events /f:xml > {xml_name}')
    print("Create xml file done")


def get_event_xml_lines():  # 현재 생성된 xml 파일을 list 로불러와 root tag 를 제거한 뒤 list 형태로 반환
    with open(file_name, 'r') as f:
        xml_lines = f.readlines()
        del xml_lines[0]
        # print(xml_lines[0])
        del xml_lines[-1]
        # print(xml_lines[-1])
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
    print(f"Last event time = {last_event_time}")
    os.system(
        f'wevtutil.exe qe "{event_name}"  /q:"*[System[TimeCreated[@SystemTime>\'{last_event_time}\']]]" /f:xml > {tmp_file}')
    with open(tmp_file) as f:
        new_xml_lines = f.readlines()
    os.remove(tmp_file)
    return new_xml_lines


def make_xml_root_tag(list_xml):  # list를 넣으면 최종적으로 root tag 생성 후 파일 생성
    #  list_xml = get_event_xml_lines()
    #  os.system(f"echo ^<?xml version=\"1.0\" encoding=\"utf-8\"?^>> {xml_name}")
    os.system(f"echo ^<Events^>> {xml_name}")
    with open(xml_name, 'a') as f:
        f.writelines(list_xml)
    os.system(f"echo ^</Events^>>> {xml_name}")


def make_xml_file():  # xml 없으면 생성하고 있으면 현재시간 까지 추가
    if os.path.isfile(xml_name):
        final_xml_lines = get_event_xml_lines() + get_new_event_xml_lines()
        make_xml_root_tag(final_xml_lines)
    elif not os.path.isfile(xml_name):
        print('Non xml file... goto create xml file')
        get_event_to_xml()

"""
def click_detection():  # 탐지를 누르게되면 호출될 함수 위의 함수와 동일
    make_xml_file()
"""

def get_event_final():
    get_event_30_min()
    abc()
    print("========GET get_event_final")
    sys.exit('process kill2')
    #  원하는 탐지 함수 추가


def sysmon_main():
    if os.path.isfile('event_tmp.xml'):
        print('The XML file is exists')
        print('Get event before 30 min')
        get_event_30_min()
        print('Start detection...')
        abc()
        print('Detection end')
        print(f'Waiting {waiting_min} min...')
    else:
        get_first_Event_to_xml()

    timer = threading.Timer(180000, sysmon_main)
    timer.start()

if __name__ == '__main__':
    sysmon_main()
