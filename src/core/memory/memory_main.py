# -*- coding: utf-8 -*-
import glob
import os
import subprocess
import sys
import json
from datetime import datetime
from multiprocessing import Process, Queue
from threading import Thread

from src.core.memory.DumpIt_execute import Dumpit_run
from src.core.memory.Volatility_plugin_func import *



def memory_main():
# if __name__ == "__main__":
    # 현재 경로를 볼라틸리티 폴더로 바꾼다 -> 덤프파일이 이 경로에 생성된다.
    os.chdir("..\\..\\program\\volatility")

    # timestamp 있는 폴더 만들기기
    path = os.getcwd()
    print("path : ", path)
    directory = str(path) +"\\"+ str(datetime.now().strftime('%Y%m%d-%H%M%S'))
    print(directory)
    try:
        if not(os.path.isdir(directory)):
            print("디렉토리좀 만들자 개잦식아")
            os.mkdir(directory)
    except OSError:
        print('Error: Creating directory. ' +  directory)

   # 덤프잇 실행시키는 함수
    Dumpit_run()

    #덤프잇으로 (최근)생성된 메모리덤프파일 가져오는 함수
    list_of_files = glob.glob('./*')  # * means all if need specific format then *.csv
    latest_file = max(list_of_files, key=os.path.getctime)
    memory_dump = os.getcwd() + latest_file[1:]

    # 예시 메모리 덤프 파일 사용
    # memory_dump = "VMW7K64-20201105-175643.raw"# 태옥
    # memory_dump = "exploit.raw" #건규
    # memory_dump = "po.raw" #건규
    # memory_dump = "WIN-UDBRDQCHDVH-20201109-123030.raw" # 익상 - networker
    # memory_dump = "allabout.raw" # 1차 통합
    # memory_dump = "WIN-UDBRDQCHDVH-20201114-073411.raw" #익상 - powerghost
    # memory_dump = "netwireDump.raw" #태옥
    # memory_dump = "w.raw" # 건규
    # memory_dump = "VMW7K64-20201112-134022.raw" #익상 - powelicks

    Profile = "Win7SP1x64"

    # 플러그인 실행
    Profile = Imageinfo(memory_dump, directory)
    Pstree(memory_dump, Profile, directory)
    Hivelist(memory_dump, Profile, directory)
    Printkey_value_Run(memory_dump, Profile, directory)
    Printkey_subkeys_Software(memory_dump, Profile, directory)
    Printkey_subkeys(memory_dump, Profile, directory)
    Netscan(memory_dump, Profile, directory)
    Psxview(memory_dump, Profile, directory)
    Ldrmodules(memory_dump, Profile, directory)
    Netscan_pstree_psxview(memory_dump, Profile, directory)
    Yarascan(memory_dump, Profile, directory)
    Malfind(memory_dump, Profile, directory)
    Dlllist_Syswow64_netscan_yarascan(memory_dump, Profile, directory)
    Detect_explorer_subprocess(memory_dump, Profile, directory)
    Result_hit_process(directory)

    print("==== memory main ======")
    sys.exit('process kill')

    # th1 = Thread(target=Pstree, args=(memory_dump, Profile))
    # th2 = Thread(target=Printkey_value_Run, args=(memory_dump, Profile))
    # th3 = Thread(target=Printkey_subkeys_Software, args=(memory_dump, Profile))
    # th4 = Thread(target=Printkey_Subkeys, args=(memory_dump, Profile))
    # th5 = Thread(target=Netscan, args=(memory_dump, Profile))
    # th6 = Thread(target=Psxview, args=(memory_dump, Profile))
    # th7 = Thread(target=Ldrmodules, args=(memory_dump, Profile))
    # th8 = Thread(target=Netscan_pstree_psxview, args=(memory_dump, Profile))
    # th9 = Thread(target=Yarascan, args=(memory_dump, Profile))
    #
    # th1.start()
    # th2.start()
    # th3.start()
    # th4.start()
    # th5.start()
    # th6.start()
    # th7.start()
    #
    # th1.join()
    # th2.join()
    # th3.join()
    # th4.join()
    # th5.join()
    # th6.join()
    # th7.join()
    #
    # th8.start()
    # th9.start()
    #
    # th8.join()
    # th9.join()
