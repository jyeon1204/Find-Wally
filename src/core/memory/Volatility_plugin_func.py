# -*- coding: utf-8 -*-
import os
import subprocess
import glob
import sys
import json
from collections import OrderedDict
import re

def Imageinfo (memory_dump, directory):
    """
    imageinfo
    """
    # vol.py -f sample\cridex.vmem imageinfo
    r = subprocess.Popen(['vol_2.6.exe', '-f', memory_dump, 'imageinfo'], stdout=subprocess.PIPE)
    out, err = r.communicate()
    if err == 0:
        print(err)

    # Profile Data
    tmp1 = str(out.splitlines()[0])
    Profile = (tmp1.split()[4]).split(',')[0]

    print("Profile(s) : " + Profile)

    # Image data and time
    line_index = 0
    for line in out.splitlines():
        if "Image date and time" in str(line):
            line_index = out.splitlines().index(line)
            break
    tmp2 = str(out.splitlines()[line_index])
    ImageDataAndTime = tmp2.split()[6] + " " + tmp2.split()[7]

    # print(ImageDataAndTime)
    print("Image data and time : " + ImageDataAndTime)
    imageinfo_data = {'Profile':Profile, 'ImageDataAndTime': ImageDataAndTime}
    with open(directory+'/imageinfo_data.json', 'w', encoding='utf-8') as make_file:
        json.dump(imageinfo_data, make_file, ensure_ascii=False, indent="\t")
    return Profile

def Pstree (memory_dump, Profile, directory):
    """
    pstree
    """
    # vol_2.6.exe -f VMW7K64-20201105-175643.raw --profile=Win7SP1x64 pstree
    r = subprocess.Popen(['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, 'pstree'], stdout=subprocess.PIPE)
    out, err = r.communicate()

    process_data = OrderedDict()
    pstree_hit_process_path = OrderedDict()
    pstree_hit_process_name = OrderedDict()
    # pid = 3368 이고 최상위 경로인 프로세스 -> 의심 프로세스
    # json 파일 추가해야함
    for line in out.splitlines()[2:]:
        tmp = str(line).split()
        addr = tmp[0][2:]
        name = (tmp[1]).split(':')[1]
        pid = tmp[2]
        ppid = tmp[3]
        process_data[pid] = {'address': addr, 'name': name, 'ppid': ppid}
        if pid == "3668" and addr == "":
            pstree_hit_process_path[pid] = {'address': addr, 'name': name, 'ppid': ppid}
        elif name == "vbc.exe" and addr == "":
            pstree_hit_process_path[pid] = {'address': addr, 'name': name, 'ppid': ppid}
        # elif re.search(r'[Pp][Oo][Ww][Ee][Rr][Gg][Hh][Oo][Ss][Tt]', name):
        #     pstree_hit_process_name[name] = {'address': addr, 'pid': pid, 'ppid': ppid}

    with open(directory+'/pstree_hit_process_path.json', 'w', encoding='utf-8') as make_file:
        json.dump(pstree_hit_process_path, make_file, ensure_ascii=False, indent="\t")

    with open(directory+'/pstree.json', 'w', encoding='utf-8') as make_file:
        json.dump(process_data, make_file, ensure_ascii=False, indent="\t")

    # 하위프로세스 추가
    subprocess_data = process_data

    for key, value in process_data.items():
        insert = OrderedDict()
        for cmp_k, cmp_v in process_data.items():
            # print(cmp_v['ppid'])
            if key == cmp_v['ppid']:
                insert[cmp_k] = cmp_v

        subprocess_data[key]['subprocess'] = insert

    with open(directory+'/sub_pstree.json', 'w', encoding='utf-8') as make_file:
        json.dump(subprocess_data, make_file, ensure_ascii=False, indent="\t")

    Detect_subprocess_powershell(directory)

def Detect_subprocess_powershell(directory):
    subprocess_powershell_hit_process = dict()
    with open(directory+'\sub_pstree.json', 'r') as f:
        SubPstree_file = json.load(f)
        if SubPstree_file:
            SubPstree_data = dict(SubPstree_file)
            exploerer_subprocess = dict()
            for k, v in SubPstree_data.items():
                # exploerer_subprocess = dict(SubPstree_data['explorer.exe']['subprocess'])
                if v['name'] == 'explorer.exe':
                    exploerer_subprocess = v['subprocess']
                    break
            print(exploerer_subprocess)
            for key, value in exploerer_subprocess.items(): # exploer 바로 하위 프로세스
                print(key)
                if value['subprocess']:
                    # print("!!!----" + str(value['subprocess']))
                    if re.search(r'[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]', str(value['subprocess'])):
                        # print("HIT")
                        subprocess_powershell_hit_process[key] = value
                    else:
                        while 1:
                            cmd = dict(value['subprocess'])
                            for cmd_k, cmd_v in cmd.items():
                                # print("----" + str(cmd_v['subprocess']))
                                if cmd_v['subprocess']:
                                    if re.search(r'[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]', str(cmd_v['subprocess'])):
                                        # print("HIT")
                                        subprocess_powershell_hit_process[key] = value
                                        break
                                    else:
                                        cmd = cmd_v['subprocess']
                            break
    # print(subprocess_powershell_hit_process)
    with open(directory+'/subprocess_powershell_hit_process.json', 'w', encoding='utf-8') as make_file:
        json.dump(subprocess_powershell_hit_process, make_file, ensure_ascii=False, indent="\t")

def Hivelist (memory_dump, Profile,directory):
    """
    hivelist
    """
    # vol_2.6.exe -f VMW7K64-20201105-175643.raw --profile=Win7SP1x64 hivelist
    r = subprocess.Popen(['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, 'hivelist'], stdout=subprocess.PIPE)
    out, err = r.communicate()
    # print(out)
    hivelist_dict = OrderedDict()
    for i in range(2, len(out.splitlines())):
        tmp = str(out.splitlines()[i])
        # print(tmp)
        virtual = tmp.split()[0][2:]
        name = tmp.split()[2][:-1]
        hivelist_dict[i - 1] = {'virtual': virtual, 'name': name}
        # print(name)

    with open(directory+'/hivelist.json', 'w', encoding='utf-8') as make_file:
        json.dump(hivelist_dict, make_file, ensure_ascii=False, indent="\t")

def Printkey_value_Run (memory_dump, Profile,directory):
    # hivelist_dict = Hivelist(memory_dump, Profile)
    hivelist_dict = dict()
    with open(directory+'\hivelist.json', 'r') as f:
        Hivelist_file = json.load(f)
        if Hivelist_file:
            hivelist_dict = dict(Hivelist_file)

    """
    printkey_value - Run
    """
    # vol_2.6.exe -f VMW7K64-20201105-175643.raw --profile=Win7SP1x64 printkey -o [virtual addr] -K "Software\Microsoft\Windows\CurrentVersion\Run"
    printkey_hit_process_value = OrderedDict()
    printkey_process = OrderedDict()
    for key, value in hivelist_dict.items():
        r = subprocess.Popen(
            ['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, 'printkey', '-o', value['virtual'], '-K',
             "Software\Microsoft\Windows\CurrentVersion\Run"], stdout=subprocess.PIPE)
        out, err = r.communicate()
        tmp = str(out.splitlines())


        tmp2 = tmp.split()
        print("-----------------------------------")
        print(tmp2)
        for i in range(len(tmp2)):
            if "Registry" in tmp2[i]:
                reg_index = i + 1
                Registry = tmp2[reg_index][:-1]
            elif "updated" in tmp2[i]:
                date_index = i + 1
                LastUpDate = tmp2[date_index]
        pname = str(value['name']).split('\\\\')[-1][:-1]
        print(pname)
        if "Values" in tmp:
            index = tmp.index("Values") +9
            tmp1 = tmp[index:]
            print(tmp1)
            if tmp1 != "":
                if 'javascript' in str(tmp1.split()[2:]).lower():
                    printkey_hit_process_value[key] = {'LastUpDate':LastUpDate,'Registry':Registry[:-1],'virtual': value['virtual'], 'name': pname,
                                                       "value": tmp[index:][42:80]}
                elif 'jscript' in str(tmp1.split()[2:]).lower():
                    printkey_hit_process_value[key] = {'LastUpDate':LastUpDate,'Registry':Registry[:-1],'virtual': value['virtual'], 'name': pname,
                                                       "value": tmp[index:][42:80]}
                elif 'encode' in str(tmp1.split()[2:]).lower():
                    printkey_hit_process_value[key] = {'LastUpDate':LastUpDate,'Registry':Registry[:-1],'virtual': value['virtual'], 'name': pname,
                                                   "value": tmp[index:][42:80]}

                printkey_process[key]={'LastUpDate':LastUpDate,'Registry':Registry[:-1],'virtual': value['virtual'], 'name': pname,
                                                   "value": tmp[index+1:]}

    with open(directory+'/printkey_Run_process.json', 'w', encoding='utf-8') as make_file:
        json.dump(printkey_process, make_file, ensure_ascii=False, indent="\t")
    with open(directory+'/printkey_Run_hit_process_value.json', 'w', encoding='utf-8') as make_file:
        json.dump(printkey_hit_process_value, make_file, ensure_ascii=False, indent="\t")

def Printkey_subkeys_Software(memory_dump, Profile,directory):
    # hivelist_dict = Hivelist(memory_dump, Profile)
    hivelist_dict = dict()
    with open(directory+'\hivelist.json', 'r') as f:
        Hivelist_file = json.load(f)
        if Hivelist_file:
            hivelist_dict = dict(Hivelist_file)
    """
    printkey_Subkeys - Software
    """
    # vol_2.6.exe -f VMW7K64-20201105-175643.raw --profile=Win7SP1x64 printkey -o [virtual addr] -K Software
    # -o 0xfffff8a005dbe010
    printkey_software_hit_process_subkeys = OrderedDict()
    for key, value in hivelist_dict.items():
        r = subprocess.Popen(
            ['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, 'printkey', '-o', value['virtual'], '-K',
             "Software"], stdout=subprocess.PIPE)
        out, err = r.communicate()

        tmp = out.splitlines()
        subkey_index = 0
        value_index = 0
        pname = str(value['name']).split('\\\\')[-1][:-1]

        tmp3 = str(tmp).split()
        print("-----------------------------------")
        print(tmp3)
        for i in range(len(tmp3)):
            if "Registry" in tmp3[i]:
                reg_index = i + 1
                Registry = tmp3[reg_index][:-1]
                # print(Registry)

        # print(pname)
        for word in tmp:
            if "Subkeys" in str(word):
                subkey_index = tmp.index(word) + 1
            elif "Value" in str(word):
                value_index = tmp.index(word) - 2
        if subkey_index != 0:
            for word in tmp[subkey_index:value_index]:
                tmp2 = str(word)[8:-1]
                # subkeys 값으로 16진수가 들어가면 hit

                # search().group() 안해도됨. search() 결과값으로 None과 None이 아닌 값이 나옴
                # print(any(sym in tmp2 for sym in '-'))
                if re.search(r'^[A-Fa-f0-9]+$', tmp2) and not any(sym in tmp2 for sym in '-'):
                    if printkey_software_hit_process_subkeys.get(key):
                        printkey_software_hit_process_subkeys[key] = {"subkeys": tmp2}
                    else:
                        printkey_software_hit_process_subkeys[key] = {'Registry':Registry,'virtual': value['virtual'],
                                                                      'name': pname, "subkeys": tmp2}
                # subskeys 값으로 특수문자가 들어가면 hit
                if any(sym in tmp2 for sym in '!@#$%^&?'):
                    if printkey_software_hit_process_subkeys.get(key):
                        printkey_software_hit_process_subkeys[key] = {"subkeys": tmp2}
                    else:
                        printkey_software_hit_process_subkeys[key] = {'Registry':Registry, 'virtual': value['virtual'], 'name': pname, 'subkeys': tmp2}

    with open(directory+'/printkey_software_hit_process_subkeys.json', 'w', encoding='utf-8') as make_file:
        json.dump(printkey_software_hit_process_subkeys, make_file, ensure_ascii=False, indent="\t")

def Printkey_subkeys(memory_dump, Profile,directory):
    # hivelist_dict = Hivelist(memory_dump, Profile)
    hivelist_dict = dict()
    with open(directory+'\hivelist.json', 'r') as f:
        Hivelist_file = json.load(f)
        if Hivelist_file:
            hivelist_dict = dict(Hivelist_file)
    """
    printkey_Subkeys
    """
    printkey_hit_process_subkeys = OrderedDict()
    for key, value in hivelist_dict.items():
        r = subprocess.Popen(
            ['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, '-o', value['virtual'], 'printkey'],
            stdout=subprocess.PIPE)
        out, err = r.communicate()

        tmp = out.splitlines()
        subkey_index = 0
        value_index = 0
        pname = str(value['name']).split('\\\\')[-1][:-1]

        tmp3 = str(tmp).split()
        print("-----------------------------------")
        print(tmp3)
        for i in range(len(tmp3)):
            if "Registry" in tmp3[i]:
                reg_index = i + 1
                Registry = tmp3[reg_index][:-1]

        for word in tmp:
            if "Subkeys" in str(word):
                subkey_index = tmp.index(word) + 1
        if subkey_index != 0:
            for word in tmp[subkey_index + 1:]:
                tmp2 = str(word)[8:-1]
                # subskeys 값으로 특수문자가 들어가면 hit
                if any(sym in tmp2 for sym in '!@#$%^&?'):
                    if printkey_hit_process_subkeys.get(key):
                        printkey_hit_process_subkeys[key] = {"subkeys": tmp2}
                    else:
                        printkey_hit_process_subkeys[key] = {'Registry':Registry, 'virtual': value['virtual'], 'name': pname,'subkeys': tmp2}
    with open(directory+'/printkey_hit_process_subkeys.json', 'w', encoding='utf-8') as make_file:
        json.dump(printkey_hit_process_subkeys, make_file, ensure_ascii=False, indent="\t")

# def Ipconfig():
#     """
#     ipconfig - 현재 PC의 IP 주소 가져오기
#     """
#     output = os.popen('ipconfig').read()
#     IpAddr = (output.splitlines()[8]).split()[-1]
#
#     # 가상환경과 맞추기 위한 하드코딩
#     # IpAddr = "192.168.23.161" # 태옥
#     IpAddr = "192.168.119.132" # 건규
#     # IpAddr = "192.168.37.128" # 네트워커
#     # IpAddr = "192.168.37.135" # 파워릭
#     # IpAddr = "192.168.37.132" # 파워고스트
#
#     print("IPv4 Address : " + IpAddr)
#     return  IpAddr

def Netscan(memory_dump, Profile,directory):
    # IpAddr = Ipconfig()
    """
    netscan - 활성화된 네트워크 연결 정보
    """
    # vol_2.6.exe -f VMW7K64-20201105-175643.raw --profile=Win7SP1x64 netscan
    r = subprocess.Popen(['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, 'netscan'], stdout=subprocess.PIPE)
    out, err = r.communicate()

    netscan_data = OrderedDict()

    # vbc.exe가 네트워크 통신하면 hit
    netscan_hit_process = OrderedDict()
    i = 0
    for line in out.splitlines()[1:]:
        i += 1
        tmp = str(line).split()
        # print(tmp)
        if len(tmp) > 5:
            protocol = tmp[1]
            local_address = (tmp[2]).split(':')[0]
            foreign_address = (tmp[3]).split(':')[0]

            # print(re.search(r'[1-9]*', tmp[5]).group())
            if re.search(r'[1-9]*', tmp[5]).group():
                # print("----------")
                pid = tmp[5]
                name = tmp[6]
                state = tmp[4]
            else:
                # print("=========")
                pid = tmp[4]
                name = tmp[5]
                state = ""

            # vbc.exe가 네트워크 통신하면 hit
            if name == "vbc.exe":
                netscan_hit_process[pid] = {'protocol':protocol, 'name': name, 'local address': local_address,
                                            'foreign address': foreign_address, 'state': state}
            # elif re.search(r'[Pp][Oo][Ww][Ee][Rr][Gg][Hh][Oo][Ss][Tt]', name):
            #     netscan_hit_process[pid] = {'name': name, 'local address': local_address,'foreign address': foreign_address, 'state': state}

            if netscan_data.get(pid):
                count = int(netscan_data[pid]['count'])
                netscan_data[pid]['count'] = str(count+1)
            else:
                netscan_data[pid] = {'protocol':protocol,'name': name, 'local address': local_address, 'foreign address': foreign_address,
                                 'state': state, 'count':'0'}
        else:
            local_address = ""
            foreign_address = ""


    with open(directory+'/netscan_hit_process.json', 'w', encoding='utf-8') as make_file:
        json.dump(netscan_hit_process, make_file, ensure_ascii=False, indent="\t")
    with open(directory+'/netscan_process.json', 'w', encoding='utf-8') as make_file:
        json.dump(netscan_data, make_file, ensure_ascii=False, indent="\t")

def Psxview (memory_dump, Profile,directory):
    """
    psxview
    """
    # vol_2.6 -f exploit.raw --profile=Win7SP1x64 psxview
    r = subprocess.Popen(['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, 'psxview'], stdout=subprocess.PIPE)
    out, err = r.communicate()

    # offset, name, pid, pslist, psscan
    psxview_data = OrderedDict()
    psxview_hit_process = OrderedDict()
    for line in out.splitlines()[2:]:
        tmp = str(line).split()
        # print(tmp)
        if len(tmp) > 2:
            psxview_offset = tmp[0][2:]
            psxview_name = tmp[1]
            psxview_pid = tmp[2]
            psxview_pslist = tmp[3]
            psxview_psscan = tmp[4]
            psxview_thrdproc = tmp[5]
            psxview_pspcid = tmp[6]
            psxview_csrss = tmp[7]
            psxview_session = tmp[8]
            psxview_deskthrd = tmp[9]
        else:
            psxview_offset = tmp[0][2:]
            psxview_name = tmp[1]
            psxview_pid = ""
            psxview_pslist =""
            psxview_psscan = ""
            psxview_thrdproc = ""
            psxview_pspcid = ""
            psxview_csrss = ""
            psxview_session = ""
            psxview_deskthrd = ""
        # Regasm 정규표현식으로 만들어서 찾자. 안나온다.
        if re.search(r'[Rr][Ee][Gg][Aa][Ss][Mm]', psxview_name):
            psxview_hit_process[psxview_name] = {'offset': psxview_offset, 'pid': psxview_pid, 'pslist': psxview_pslist,
                                      'psscan': psxview_psscan, 'thrdproc': psxview_thrdproc, 'pspcid': psxview_pspcid,
                                      'csrss': psxview_csrss, 'session': psxview_session, 'deskthrd':psxview_deskthrd}
        if re.search(r'(True|False)', psxview_pid):
            # 프로세스 이름이 없어서 pid에 T or F 가 들어갈때
            print("HIT psxview_pid is string : " + psxview_pid )
            # psxview_name = "", 이후 요소들은 한칸씩 땡겨줘야함
            psxview_name = ""
            psxview_pid = tmp[1]
            psxview_pslist = tmp[2]
            psxview_psscan = tmp[3]
            psxview_thrdproc = tmp[4]
            psxview_pspcid = tmp[5]
            psxview_csrss = tmp[6]
            psxview_session = tmp[7]
            psxview_deskthrd = tmp[8]
            psxview_hit_process[psxview_name] = {'offset': psxview_offset, 'pid': psxview_pid, 'pslist': psxview_pslist,
                                                 'psscan': psxview_psscan, 'thrdproc': psxview_thrdproc,
                                                 'pspcid': psxview_pspcid,
                                                 'csrss': psxview_csrss, 'session': psxview_session,
                                                 'deskthrd': psxview_deskthrd}
        elif psxview_pid == "" or  int(psxview_pid) > 32768:
            psxview_hit_process[psxview_name] = {'offset': psxview_offset, 'pid': psxview_pid, 'pslist': psxview_pslist,
                                                 'psscan': psxview_psscan, 'thrdproc': psxview_thrdproc,
                                                 'pspcid': psxview_pspcid,
                                                 'csrss': psxview_csrss, 'session': psxview_session,
                                                 'deskthrd': psxview_deskthrd}

        elif any(sym in psxview_name for sym in '!@#$%^&?/\\|') or any(sym in psxview_offset for sym in '!@#$%^&?/\\|'):
            # 프로세스 이름에 특수문자가 들어갈때
            print("HIT psxview_name 특수문자: " + psxview_name)
            psxview_hit_process[psxview_name] = {'offset': psxview_offset, 'pid': psxview_pid, 'pslist': psxview_pslist,
                                                 'psscan': psxview_psscan, 'thrdproc': psxview_thrdproc,
                                                 'pspcid': psxview_pspcid,
                                                 'csrss': psxview_csrss, 'session': psxview_session,
                                                 'deskthrd': psxview_deskthrd}
        elif re.search(r'^[xX][A-Fa-f0-9]*$', psxview_name) or re.search(r'^[xX][A-Fa-f0-9]*$', psxview_offset):
            # 프로세스 이름이 16진수일때
            print("HIT psxview_name 16: " + psxview_name)
            psxview_hit_process[psxview_name] = {'offset': psxview_offset, 'pid': psxview_pid, 'pslist': psxview_pslist,
                                                 'psscan': psxview_psscan, 'thrdproc': psxview_thrdproc,
                                                 'pspcid': psxview_pspcid,
                                                 'csrss': psxview_csrss, 'session': psxview_session,
                                                 'deskthrd': psxview_deskthrd}
        elif psxview_thrdproc:
            if not psxview_pslist and not psxview_psscan and not psxview_pspcid:
                if not psxview_csrss and not psxview_session and not psxview_deskthrd:
                    psxview_hit_process[psxview_name] = {'offset': psxview_offset, 'pid': psxview_pid,
                                                         'pslist': psxview_pslist,
                                                         'psscan': psxview_psscan, 'thrdproc': psxview_thrdproc,
                                                         'pspcid': psxview_pspcid,
                                                         'csrss': psxview_csrss, 'session': psxview_session,
                                                         'deskthrd': psxview_deskthrd}

        psxview_data[psxview_name] = {'offset': psxview_offset, 'pid': psxview_pid, 'pslist': psxview_pslist,
                                      'psscan': psxview_psscan, 'thrdproc': psxview_thrdproc, 'pspcid': psxview_pspcid,
                                      'csrss': psxview_csrss, 'session': psxview_session, 'deskthrd':psxview_deskthrd }

    with open(directory+'/psxview_hit_process.json', 'w', encoding='utf-8') as make_file:
        json.dump(psxview_hit_process, make_file, ensure_ascii=False, indent="\t")
    with open(directory+'/psxview_process.json', 'w', encoding='utf-8') as make_file:
        json.dump(psxview_data, make_file, ensure_ascii=False, indent="\t")

def Ldrmodules(memory_dump, Profile,directory):
    """
    ldrmodules
    """
    # vol_2.6.exe -f VMW7K64-20201105-175643.raw --profile=Win7SP1x64 ldrmodules
    r = subprocess.Popen(['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, 'ldrmodules'],
                         stdout=subprocess.PIPE)
    out, err = r.communicate()

    ldrmodules_hit_process = OrderedDict()
    for line in out.splitlines()[2:]:
        tmp1 = str(line).split()
        pid = tmp1[1]
        process = tmp1[2]
        base = tmp1[3]
        mapped_path = tmp1[7]
        path_list = os.path.normpath(mapped_path)
        if "Roaming" in path_list:
            tmp2 = path_list[path_list.index("Roaming"):]
            for word in tmp2:
                # \Roaming 이후 경로에 16진수가 오면 hit
                if re.search(r'^[A-Fa-f0-9]+$', word):
                    # 모든 반환값의 형태가 <re.Match object; span=(0, 4), match='3668'>
                    if ldrmodules_hit_process.get(process):
                        ldrmodules_hit_process[process]["mapped_path_16"] = mapped_path
                    else:
                        ldrmodules_hit_process[process] = {'pid': pid, 'base': base, 'mapped_path_16': mapped_path}
        if "jscript.dll" in path_list:
            if ldrmodules_hit_process.get(process):
                ldrmodules_hit_process[process]["mapped_path_dns"] = mapped_path
            else:
                ldrmodules_hit_process[process] = {'pid': pid, 'base': base, 'mapped_path_jscript': mapped_path}
    with open(directory+'/ldrmodules_hit_process.json', 'w', encoding='utf-8') as make_file:
        json.dump(ldrmodules_hit_process, make_file, ensure_ascii=False, indent="\t")

    ldrmodules_process_dll = dict()
    if "dnsapi.dll" in path_list:
        if ldrmodules_process_dll.get(process):
            ldrmodules_process_dll[process]["mapped_path_dns"] = mapped_path
        else:
            ldrmodules_process_dll[process] = {'pid': pid, 'base': base, 'mapped_path_dns': mapped_path}
    with open(directory+'/ldrmodules_process_dll.json', 'w', encoding='utf-8') as make_file:
        json.dump(ldrmodules_process_dll, make_file, ensure_ascii=False, indent="\t")

def Netscan_pstree_psxview (memory_dump, Profile,directory):
    """
    netsacn.json - pstree_hit_proces_path.json & psxview_process.json
    """
    candidate_process1 = []
    with open(directory+'\pstree_hit_process_path.json', 'r') as f:
        PstreeHitProcessPath_file = json.load(f)
        if PstreeHitProcessPath_file:
            PstreeHitProcessPath_data = dict(PstreeHitProcessPath_file)
            for key, value in PstreeHitProcessPath_data.items():
                if value['address'] == "":
                    candidate_process1.append(key)

    candidate_process2 = []
    with open(directory+'\psxview_process.json', 'r') as f:
        PsxviewProcess_file = json.load(f)
    if PsxviewProcess_file:
        PsxviewProcess_data = dict(PsxviewProcess_file)
        for key, value in PsxviewProcess_data.items():
            if not value['pslist'] and not value['psscan']:
                if not value['thrdproc'] and not value['pspcid']:
                    candidate_process2.append(value['pid'])

    candidate_process = []
    if candidate_process1 and candidate_process2:
        for cmp_pid1 in candidate_process2:
            for cmp_pid2 in candidate_process1:
                if cmp_pid1 == cmp_pid2:
                    candidate_process.append(cmp_pid1)

    netscan_and_psxview_hit_process = OrderedDict()
    with open(directory+'\\netscan_process.json', 'r') as f:
        netscan_process_file = json.load(f)
        if netscan_process_file:
            netscan_process_data = dict(netscan_process_file)
            for key, value in PsxviewProcess_data.items():
                for cmd in candidate_process:
                    if key == cmd:
                        netscan_and_psxview_hit_process[key] = {'name': value['name'],
                                                                'local address': value['local address'],
                                                            'foreign address': value['foreign address']}

    with open(directory+'/netscan_and_psxview_hit_process.json', 'w', encoding='utf-8') as make_file:
        json.dump(netscan_and_psxview_hit_process, make_file, ensure_ascii=False, indent="\t")

def Yarascan(memory_dump, Profile,directory):
    """
    yarascan
    """
    # 의심 프로세스 한꺼번에 모으기
    candidate_process = []
    with open(directory+'\\psxview_hit_process.json', 'r') as f:
        psxview_hit_process_file = json.load(f)
        if psxview_hit_process_file:
            PsxviewHitProcess_data = dict(psxview_hit_process_file)
            for key, value in PsxviewHitProcess_data.items():
                candidate_process.append(key)
    # print("candidate_process_psxview :" + candidate_process_psxview)
    # if candidate_process:
    #     print("candidate_process_psxview :" + str(candidate_process))


    with open(directory+'\\pstree_hit_process_path.json', 'r') as f:
        pstree_hit_process_path_file = json.load(f)
        if pstree_hit_process_path_file:
            PstreeHitProcessPath_data = dict(pstree_hit_process_path_file)
            # key 값이 process name
            for key, value in PstreeHitProcessPath_data.items():
                # 키값 카빙 필요
                # tmp = key.split('\\')
                candidate_process.append(key)
    # print("candidate_process_psxview :"+candidate_process_pstree)
    # if candidate_process:
    #     print("candidate_process_pstree :" + str(candidate_process))

    with open(directory+'\\printkey_software_hit_process_subkeys.json') as f:
        PrintkeySoftwareHitProcessSubkeys_file = json.load(f)
        if PrintkeySoftwareHitProcessSubkeys_file:
            PrintkeySoftwareHitProcessSubkeys_data = dict(PrintkeySoftwareHitProcessSubkeys_file)
            # 프로세스 이름 = value['name']
            for key, value in PrintkeySoftwareHitProcessSubkeys_data.items():
                # 값 카빙 필요
                tmp = (value['name']).split('\\\\')[3:]
                candidate_process.append(tmp[:-1])
    # print("candidate_process_psxview :"+candidate_process_pstree)
    # if candidate_process:
    #     print("\printkey_software_hit_process_subkeys.json :" + str(candidate_process))

    with open(directory+'\printkey_Run_hit_process_value.json') as f:
        PrintkeyRunHitProcessValue_file = json.load(f)
        if PrintkeyRunHitProcessValue_file:
            PrintkeyRunHitProcessValue_data = dict(PrintkeyRunHitProcessValue_file)
            # 프로세스 이름 = value['name']
            for key, value in PrintkeyRunHitProcessValue_data.items():
                # 값 카빙 필요
                tmp = str(value['name'])
                tmp = tmp.split("\\\\")[-1][:-1]
                candidate_process.append(tmp)
    # if candidate_process:
    #     print(".\json\printkey_Run_hit_process_value.json :" + str(candidate_process))


    with open(directory+'\printkey_hit_process_subkeys.json') as f:
        PrintkeyHitProcessSubkeys_file = json.load(f)
        if PrintkeyHitProcessSubkeys_file:
            PrintkeyHitProcessSubkeys_data = dict(PrintkeyHitProcessSubkeys_file)
            # 프로세스 이름 = value['name']
            for key, value in PrintkeyHitProcessSubkeys_data.items():
                # 값 카빙 필요
                tmp = str(value['name'])
                tmp = tmp.split("\\\\")[-1][:-1]
                candidate_process.append(tmp)
    # if candidate_process:
    #     print(".\json\printkey_hit_process_subkeys.json :" + str(candidate_process))

    with open(directory+"\\\\netscan_and_psxview_hit_process.json") as f:
        NetscanAndPsxviewHitProcess_file = json.load(f)
        if NetscanAndPsxviewHitProcess_file:
            NetscanAndPsxviewHitProcess_data = dict(NetscanAndPsxviewHitProcess_file)
            # 프로세스 이름 = value['name']
            for key, value in NetscanAndPsxviewHitProcess_data.items():
                # 값 카빙 필요
                tmp = str(value['name'])
                tmp = tmp.split("\\\\")[-1]
                candidate_process.append(tmp)
    # if candidate_process:
    #     print(".\json\\\\netscan_and_psxview_hit_process.json :" + str(candidate_process))

    with open(directory+'\ldrmodules_hit_process.json') as f:
        LdrmodulesHitProcess_file = json.load(f)
        if LdrmodulesHitProcess_file:
            LdrmodulesHitProcess_data = dict(LdrmodulesHitProcess_file)
            # 프로세스 이름 = value['name']
            for key, value in LdrmodulesHitProcess_data.items():
                # 값 카빙 필요
                tmp = str(key)
                tmp = tmp.split("\\\\")[-1]
                candidate_process.append(tmp)

    # if candidate_process:
    #     print(".\json\\\\netscan_and_psxview_hit_process.json :" + str(candidate_process))
    if candidate_process:
        # print("candidate_process :" + str(candidate_process))
        # print("------",candidate_process)
        # tmp_set = candidate_process
        # candidate_process = list(tmp_set)
        yarascan_hit_process = OrderedDict()
        if candidate_process:
            for name in candidate_process:
                print(name)
                r = subprocess.Popen(['vol_2.6.exe', '-f', memory_dump, '--profile='+Profile, 'yarascan', '--yara-rules='+str(name)], stdout=subprocess.PIPE)
                out, err = r.communicate()
                tmp = str(out).split('Rule')
                for cmp in tmp:
                    # print(re.search("52 70 63", cmp))
                    if re.search("52 70 63", cmp):
                        string = re.search(r'[Rr][Pp][Cc]', cmp)
                        # print("hit---------------------------------")
                        yarascan_hit_process[str(name)] = {"signature": "RPC"}

            with open(directory+'/yarascan_hit_process.json', 'w', encoding='utf-8') as make_file:
                json.dump(yarascan_hit_process, make_file, ensure_ascii=False, indent="\t")

def Malfind (memory_dump, Profile,directory):
    # vol.exe -f netwireDump.raw —profile=Win7SP1x64 malfind -p 3520
    # r = subprocess.Popen(['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, 'malfind', '-p'],stdout=subprocess.PIPE)
    # out, err = r.communicate()

    # 의심되는 vbc.exe 프로세스 아이디를 가져오기
    with open(directory+"\\\\pstree_hit_process_path.json") as f:
        PstreeHitProcessPath_file = json.load(f)
        if PstreeHitProcessPath_file:
            PstreeHitProcessPath_data = dict(PstreeHitProcessPath_file)
            if PstreeHitProcessPath_data.get('vbc.exe'):
                vbc_exe_pid = PstreeHitProcessPath_data['vbc.exe']['pid']
                r = subprocess.Popen(['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, 'malfind', '-p', vbc_exe_pid],stdout=subprocess.PIPE)
                out, err = r.communicate()
                tmp = str(out.splitlines()[3:6])

                malfind_hit_process = OrderedDict()
                if re.search(r'[Mm][Zz]', tmp):
                    # print(re.search(r'[Mm][Zz]', tmp).group())
                    malfind_hit_process['vbc.exe'] = {'pid':vbc_exe_pid, 'signature':re.search(r'[Mm][Zz]', tmp).group()}

                with open(directory+'/malfind_hit_process.json', 'w', encoding='utf-8') as make_file:
                    json.dump(malfind_hit_process, make_file, ensure_ascii=False, indent="\t")

def Detect_explorer_subprocess (memory_dump, Profile,directory):
    candidate_process = dict()

    # explorer 하위 프로세스 목록 가져오기
    with open(directory+'\\sub_pstree.json', 'r') as f:
        SubPstree_file = json.load(f)
        if SubPstree_file:
            SubPstree_data = dict(SubPstree_file)
            # explorer_subprocess = dict(SubPstree_data['explorer.exe']['subprocess'])
            for k, v in SubPstree_data.items():
                if v['name'] == 'explorer.exe':
                    explorer_subprocess = v['subprocess']
                    break
    # netcscan 가져와서 explorer 하위 프로세스가 네트워크 통신하는 지 확인하기
    with open(directory+'\\netscan_process.json', 'r') as f:
        NetscanProcess_file = json.load(f)
        if NetscanProcess_file and explorer_subprocess:
            NetscanProcess_data = dict(NetscanProcess_file)
            for N_key, N_value in NetscanProcess_data.items():
                # N_key : pid, N_value : { name, local address, foreign address, state}
                # print("N : " + str(N_key) + " ---- " + str(N_value))
                for E_key, E_value in explorer_subprocess.items():
                    # E_key : process name, E_value : { address, pid, ppid, subprocess}
                    # print("E : " + str(E_key) + " ---- " + str(E_value))
                    if N_key == E_key:
                        print("hit: "+N_value['name'])
                        candidate_process[E_value['name']] = {'pid':N_key}
                        # print(str(candidate_process))

    # ldrmodules 플러그인에서 dnsapi.dll 을 사용하는 프로세스 뽑아 놓은 ldrmodules_process_dll.json 이용하기
    # 의심프로세스 후보에서 dnaspi.dll를 사용하는지 확인
    tmp_dict = dict()
    with open(directory+'\\ldrmodules_process_dll.json', 'r') as f:
        LdrmodulesHitProcess_file = json.load(f)
        if LdrmodulesHitProcess_file:
            LdrmodulesHitProcess_data = dict(LdrmodulesHitProcess_file)
            for L_key, L_value in LdrmodulesHitProcess_data.items():
                # print("L_key : "+L_key)
                for C_key, C_value in candidate_process.items():
                    # print("C_key : " +C_key)
                    if L_value['pid'] == C_value['pid']:
                        tmp_dict[C_key] = C_value
            candidate_process = tmp_dict
            print("candidate_process : "+str(candidate_process))

    # yarascan 플러그인을 사용해서 의심프로세스 확률 높이기 - "socket" or "http"
    # vol_2.6.exe -f WIN-UDBRDQHDVH-20201114-073411.raw —profile=Win7SP1x64 yarascan —yara-rules = "socket" -p 2260
    word = ["socket", "http"]
    if candidate_process:
        print("?????????????",candidate_process)
        for key, value in candidate_process.items():
            pid = value['pid']
            print(pid)
            # vol_2.6.exe -f WIN-UDBRDQCHDVH-20201114-073411.raw --profile=Win7SP1x64 yarascan --yara-rules=socket -p 2260
            r = subprocess.Popen(['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, 'yarascan', '--yara-rules='+word[0], '-p', pid], stdout=subprocess.PIPE)
            out, err = r.communicate()
            tmp = str(out).split('Rule')[1:]
            # 출력물 가공하기
            string_list = []
            for k in range(0, len(tmp)):
                tmp1 = tmp[k].split("0x")[1:]
                # print(tmp1)
                for i in range(0, len(tmp1)):
                    tmp2 = (tmp1[i][60:]).split('\\r\\n')[0]
                    string_list.append(tmp2)
            string = ""
            url = ""
            for i in range(0, len(string_list)):
                string += string_list[i]
                # print(string)
                # 출력물에서 검색하기 - ".com"
                # print(re.search(r'(.com)', string).group())
            tmp3 = string.split(".")
            for k in range(0, len(tmp3)):
                # 출력물에 "com" 이 있으면
                if tmp3 != "" and re.search(r'(com)', tmp3[k]):
                    # print(re.search(r'(com)', tmp3[k]).group())
                    if tmp3[k-1] != "":
                        if tmp3[k-2] != "":
                            url = tmp3[k-2] + "." + tmp3[k-1]+ "." + tmp3[k]
                        else:
                            url = tmp3[k - 1]+ "." + tmp3[k]
                    break

            print("url : "+ url)
            # print("--------------------------------")
            # 찾은 의심스러운 주소를 가지고 한 번 더 검사
            if url != "":
                result = subprocess.Popen(['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, 'yarascan', '--yara-rules=' + url, '-p', pid], stdout=subprocess.PIPE)
                out, err = result.communicate()
                # print(out)
                TMP = str(out).split('Rule')[1:]
                # 출력물 가공하기
                string_list = []
                for k in range(0, len(TMP)):
                    TMP1 = TMP[k].split("0x")[1:]
                    # print(TMP1)
                    for i in range(0, len(TMP1)):
                        TMP2 = (TMP1[i][60:]).split('\\r\\n')[0]
                        string_list.append(TMP2)

                string = ""
                for i in range(0, len(string_list)):
                        string += string_list[i]
                # print(string_list)
                if re.search(r'[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]', str(string)):
                    # print(re.search(r'[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]', str(string)).group())
                    tmp_dict[key] = value
                    tmp_dict[key]['url'] = url
                    tmp_dict[key]['signature'] = str(re.search(r'[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]', str(string)).group())
    candidate_process = tmp_dict
    print("Detect_explorer_subprocess : ",candidate_process)
    with open(directory+'/Detect_explorer_subprocess_hit_process.json', 'w', encoding='utf-8') as make_file:
        json.dump(candidate_process, make_file, ensure_ascii=False, indent="\t")


def Dlllist_Syswow64_netscan_yarascan (memory_dump, Profile,directory):
    # vol_2.6.exe -f waanermine.raw --profile=Win7SP1x64 dlllist
    r = subprocess.Popen(['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, 'dlllist'],
                         stdout=subprocess.PIPE)
    out, err = r.communicate()
    tmp = out.splitlines()
    index = 0
    pid = 0
    pname = "svchost"
    candidate_process = dict()
    for n in range(len(tmp)):
        # print(tmp[n])
        if re.search(r'[Ss][Yy][Ss][Ww][Oo][Ww]64', str(tmp[n])):
            if re.search(r'[Ss][Vv][Cc][Hh][Oo][Ss][Tt]', str(tmp[n])):
                # print("HIT")
                index = n
                # print(index)
                break

    if index != 0:
        print(tmp[index-1])
        print(tmp[index])
        if "pid" in str(tmp[index-1]):
            tmp1 = str(tmp[index-1]).split()
            pid = tmp1[2][:-1]
            print(pid)
    else:
        print("Dlllist_Syswow64_netscan_yarascan() function : not find index number")

    hit = False

    # pstree 에서 svchost의 pid를 ppid로 가진 프로세스들 찾기 - svchost.exe의 subprocess 찾기
    svchost_subprocess = dict()
    with open(directory+'\\pstree.json', 'r') as f:
        Pstree_file = json.load(f)
        if Pstree_file:
            Pstree_data = dict(Pstree_file)
            for key, value in Pstree_data.items():
                if key == str(value['ppid']):
                    # print("HIT")
                    svchost_subprocess[key] = {'name':value['name']}
    if svchost_subprocess:
        print(svchost_subprocess)
        # netscan 을 통해 svchost의 subporcess 가 네트워크 통신을 도배하지 않았는지 확인하기
        # 도배 15개 이상 의심프로세스 간주
        with open(directory+'\\netscan_process.json', 'r') as f:
            NetscanProcess_file = json.load(f)
            if NetscanProcess_file:
                NetscanProcess_data = dict(NetscanProcess_file)
                # print("=========",svchost_subprocess)
                for s_key, s_value in svchost_subprocess.items():
                    for n_key, n_value in NetscanProcess_data.items():
                        # print(n_key, s_value['pid'])
                        if n_key == s_value['pid'] and n_value['state'] == "SYN_SENT":
                            if int(n_value['count']) >= 15:
                                # print("HITHITHITHIT", s_key)
                                candidate_process[s_value['pid']] = {'name': s_key}



    # yarascan을 통해서 svchost 문자열과 pid를 검색하여 delete 혹은 HalPlugins, Ping.returned 문자열이 들어가는지 검사
    if pid != 0:
        print("-------yarascan--------")
        r = subprocess.Popen(['vol_2.6.exe', '-f', memory_dump, '--profile=' + Profile, 'yarascan', '--yara-rules='+pname, '-p', pid],
            stdout=subprocess.PIPE)
        out, err = r.communicate()

        # 출력물 가공하기
        tmp = str(out).split('Rule')[1:]
        string_list = []
        for k in range(0, len(tmp)):
            tmp1 = tmp[k].split("0x")[1:]
            # print(tmp1)
            for i in range(0, len(tmp1)):
                tmp2 = (tmp1[i][60:]).split('\\r\\n')[0]
                string_list.append(tmp2)
        string = ""
        url = ""
        for i in range(0, len(string_list)):
            string += string_list[i]
        print(string)

        if re.search(r'[Dd][Ee][Ll][Ee][Tt][Ee]', string):
            print("Delete")
            hit= True

        elif re.search(r'[Hh][Aa][Ll][Pp][Ll][Uu][Gg][Ii][Nn][Ss]', string):
            print("HalPlugines")
            hit = True
        elif  re.search(r'[Pp][Ii][Nn][Gg].[Rr][Ee][Tt][Uu][Rr][Nn][Ee][Dd]', string):
            print("Ping.returned")
            hit = True

        if hit:
            candidate_process[pid] = {'name': pname}
        if candidate_process:
            with open(directory+'/Dlllist_Syswow64_netscan_yarascan_hit_process.json', 'w', encoding='utf-8') as make_file:
                json.dump(candidate_process, make_file, ensure_ascii=False, indent="\t")
        else:
            candidate_process = {}
            with open(directory+'/Dlllist_Syswow64_netscan_yarascan_hit_process.json', 'w', encoding='utf-8') as make_file:
                json.dump(candidate_process, make_file, ensure_ascii=False, indent="\t")

def Result_hit_process(directory):
    process = dict()
    registry = dict()
    # key : 프로세스 이름
    # value : 'pid'

    # pstree_hit_process_path.json
    with open(directory+'\\pstree_hit_process_path.json', 'r') as f:
        Pstree_file = json.load(f)
        if Pstree_file:
            Pstree_data = dict(Pstree_file)
            for key, value in Pstree_data.items():
                process[value['name']] = {'pid':key}
            print("pstree clear : ", process)

    # subprocess_powershell_hit_process.json
    with open(directory+'\\subprocess_powershell_hit_process.json', 'r') as f:
        SubprocessPowershell_file = json.load(f)
        if SubprocessPowershell_file:
            SubprocessPowershell_data = dict(SubprocessPowershell_file)
            for key, value in SubprocessPowershell_data.items():
                process[value['name']] = {'pid':key}
            print("SubprocessPowershell : ", process)

    # printkey_Run_hit_process_value.json
    with open(directory+'\\printkey_Run_hit_process_value.json', 'r') as f:
        PrintkeyRun_file = json.load(f)
        if PrintkeyRun_file:
            PrintkeyRun_data = dict(PrintkeyRun_file)
            for key, value in PrintkeyRun_data.items():
                if not process.get(value['Registry']):
                    registry[value['Registry']] = {'pid':""}
            print("PrintkeyRun : ", process)

    # printkey_software_hit_process_subkeys.json
    with open(directory+'\\printkey_software_hit_process_subkeys.json', 'r') as f:
        PrintkeySoftware_file = json.load(f)
        if PrintkeySoftware_file:
            PrintkeySoftware_data = dict(PrintkeySoftware_file)
            for key, value in PrintkeySoftware_data.items():
                if not process.get(value['Registry']):
                    registry[value['Registry']] = {'pid':""}
            print("PrintkeySoftware : ", process)

    # printkey_hit_process_subkeys.json
    with open(directory+'\\printkey_hit_process_subkeys.json', 'r') as f:
        Printkey_file = json.load(f)
        if Printkey_file:
            Printkey_data = dict(Printkey_file)
            for key, value in Printkey_data.items():
                if not process.get(value['Registry']):
                    registry[value['Registry']] = {'pid':""}
            print("Printkey : ", process)

    # netscan_hit_process.json
    with open(directory+'\\netscan_hit_process.json', 'r') as f:
        Netscan_file = json.load(f)
        if Netscan_file:
            Netscan_data = dict(Netscan_file)
            for key, value in Netscan_data.items():
                if not process.get(value['name']):
                    process[value['name']] = {'pid':key}
            print("Netscan : ", process)

    # psxview_hit_process.json
    with open(directory+'\\psxview_hit_process.json', 'r') as f:
        Psxview_file = json.load(f)
        if Psxview_file:
            Psxview_data = dict(Psxview_file)
            for key, value in Psxview_data.items():
                if not process.get(key):
                    process[key] = {'pid':value['pid']}
            print("Psxview : ", process)

    # ldrmodules_hit_process.json
    with open(directory+'\\ldrmodules_hit_process.json', 'r') as f:
        Ldrmodules_file = json.load(f)
        if Ldrmodules_file:
            Ldrmodules_data = dict(Ldrmodules_file)
            for key, value in Ldrmodules_data.items():
                if not process.get(key):
                    process[key] = {'pid':value['pid']}
            print("Ldrmodules : ", process)

    # netscan_and_psxview_hit_process.json
    with open(directory+'\\netscan_and_psxview_hit_process.json', 'r') as f:
        NetscanPsxview_file = json.load(f)
        if NetscanPsxview_file:
            NetscanPsxview_data = dict(NetscanPsxview_file)
            for key, value in NetscanPsxview_data.items():
                if not process.get(value['name']):
                    process[key] = {'pid':value['pid']}
            print("NetscanPsxview : ", process)

    # yarascan_hit_process.json
    with open(directory+'\\yarascan_hit_process.json', 'r') as f:
        Yarascan_file = json.load(f)
        if Yarascan_file:
            Yarascan_data = dict(Yarascan_file)
            for key, value in Yarascan_data.items():
                if not process.get(key):
                    process[key] = {}
            print("Yarascan : ", process)

    # Detect_explorer_subprocess_hit_process.json
    with open(directory+'\\Detect_explorer_subprocess_hit_process.json', 'r') as f:
        DetectExplorer_file = json.load(f)
        if DetectExplorer_file:
            DetectExplorer_data = dict(DetectExplorer_file)
            for key, value in DetectExplorer_data.items():
                if not process.get(key):
                    process[key] = {'pid':value['pid']}
            print("DetectExplorer : ", process)

    # Dlllist_Syswow64_netscan_yarascan_hit_process
    if os.path.isfile(directory+'\\Dlllist_Syswow64_netscan_yarascan_hit_process.json'):
        with open(directory+'\\Dlllist_Syswow64_netscan_yarascan_hit_process.json', 'r') as f:
            DlllistSyswow64_file = json.load(f)
            if DlllistSyswow64_file:
                DlllistSyswow64_data = dict(DlllistSyswow64_file)
                for key, value in DlllistSyswow64_data.items():
                    if not process.get(key):
                        process[value['name']] = {'pid':key}
                print("DlllistSyswow64 : ", process)
    print("ALL Detect END")

    # 모은 hit process 들을 하나의 json으로 산출
    with open(directory+'/Result_hit_process.json', 'w', encoding='utf-8') as make_file:
        json.dump(process, make_file, ensure_ascii=False, indent="\t")

    # 모은 hit registry 들을 하나의 json으로 산출
    with open(directory+'/Result_hit_registry.json', 'w', encoding='utf-8') as make_file:
        json.dump(registry, make_file, ensure_ascii=False, indent="\t")

    return