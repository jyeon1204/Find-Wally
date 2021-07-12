# import ProcessTree.Process as Process
from datetime import datetime

#Function to create Entry object
from src.core.Sysmon.ProcessTree import Process


def get_entreis(xml_node):
    for event in xml_node:
        try:
            yield Entry(event)
        except:
            continue

def utc_to_asia_seoul(str):
    import pytz
    dt_strptime = datetime.strptime(str, '%Y-%m-%d %H:%M:%S.%f')
    tz_kst = pytz.timezone('Asia/Seoul')
    dt_kst = pytz.utc.localize(dt_strptime)

    dt_utc_from_kst = dt_kst.astimezone(tz_kst)
    res = dt_utc_from_kst.strftime('%Y-%m-%d %H:%M:%S.%f')
    return res

class Entry():
    def __init__(self,event):
        self._event = event
        self._namespace = event.nsmap[None]

    def get_xpath(self, path):
        ns = {"ns": self._namespace}
        route = f".//ns:{path}"
        return self._event.xpath(route,namespaces=ns)[0]
    
    def get_eid(self):
        path = 'EventID'
        return int(self.get_xpath(path).text)

    def is_sysmon_proc_created_event(self):
        return self.get_eid() == 1

    def is_sysmon_proc_network_connected_event(self):
        return self.get_eid() == 3

    def is_sysmon_proc_exited_event(self):
        return self.get_eid() == 5
    
    def is_sysmon_proc_drive_loaded_event(self):
        return self.get_eid() == 6
    
    def is_sysmon_proc_image_loaded_event(self):
        return self.get_eid() == 7

    def is_sysmon_proc_create_remote_thread_event(self):
        return self.get_eid() == 8

    def is_sysmon_proc_acess_event(self):
        return self.get_eid() == 10

    def is_sysmon_proc_file_created_event(self):
        return self.get_eid() == 11

    def is_sysmon_proc_registry_add_event(self):
        if self.get_eid() == 12:
            return True

    def is_sysmon_proc_registry_set_event(self):
        if self.get_eid() == 13:
            return True

    def is_sysmon_proc_registry_rename_event(self):
        if self.get_eid() == 14:
            return True

    def is_sysmon_proc_wmi_event(self):
        if self.get_eid() == 19 or self.get_eid() == 20 or self.get_eid() == 21:
            return True

    def is_sysmon_proc_dns_event(self):
        return self.get_eid() == 22

    def is_sysmon_proc_file_deleted_event(self):
        return self.get_eid() == 23

    def is_sysmon_proc(self):
        p = [3,7,8,11,12,13,14,22]

        if self.get_eid() in p:
            return True   
        return False

    def get_process_from_1_event(self):
        path = self.get_xpath("Data[@Name='Image']").text
        pid = int(self.get_xpath("Data[@Name='ProcessId']").text)
        ppid = int(self.get_xpath("Data[@Name='ParentProcessId']").text)
        cmdline = self.get_xpath("Data[@Name='CommandLine']").text
        ppname = self.get_xpath("Data[@Name='ParentImage']").text
        originalfilename = self.get_xpath("Data[@Name='OriginalFileName']").text
        p = Process.EventIdOneFive(pid, ppid, cmdline, ppname,path,originalfilename)
        p.begin = str(utc_to_asia_seoul(self.get_xpath("Data[@Name='UtcTime']").text))
        return p
    
    def get_process_from_3_event(self):
        pid = int(self.get_xpath("Data[@Name='ProcessId']").text)
        path = self.get_xpath("Data[@Name='Image']").text
        protocal = self.get_xpath("Data[@Name='Protocol']").text
        srcip = self.get_xpath("Data[@Name='SourceIp']").text
        srcport = self.get_xpath("Data[@Name='SourcePort']").text
        dstip = self.get_xpath("Data[@Name='DestinationIp']").text
        dstport = self.get_xpath("Data[@Name='DestinationPort']").text
        p = Process.EventIdThree(pid,protocal,srcip,srcport,dstip,dstport,path)
        p.time = str(utc_to_asia_seoul(self.get_xpath("Data[@Name='UtcTime']").text))
        return p
    
    def get_process_from_5_event(self):
        path = self.get_xpath("Data[@Name='Image']").text
        pid = int(self.get_xpath("Data[@Name='ProcessId']").text)
        ppid = 0
        cmdline = "UNKNOWN"
        ppname = "UNKNOWN"
        originalfilename = "UNKNOWN"

        p = Process.EventIdOneFive(pid, ppid, cmdline, ppname,path,originalfilename)
        p.end = str(utc_to_asia_seoul(self.get_xpath("Data[@Name='UtcTime']").text))
        return p
    
    def get_process_from_8_event(self):
        path = self.get_xpath("Data[@Name='SourceImage']").text
        pid = int(self.get_xpath("Data[@Name='SourceProcessId']").text)
        dstpath = self.get_xpath("Data[@Name='TargetImage']").text
        dstpid = int(self.get_xpath("Data[@Name='TargetProcessId']").text)
        startAddress = int(self.get_xpath("Data[@Name='StartAddress']").text,16)
        startModule = self.get_xpath("Data[@Name='StartModule']").text
        startFuction = self.get_xpath("Data[@Name='StartFunction']").text
        p = Process.EventIdEight(pid, path, dstpid, dstpath,startAddress,startModule,startFuction)
        p.time = str(utc_to_asia_seoul(self.get_xpath("Data[@Name='UtcTime']").text))
        return p
    
    def get_process_from_11_event(self):
        pid = int(self.get_xpath("Data[@Name='ProcessId']").text)
        path = self.get_xpath("Data[@Name='Image']").text
        fileName = self.get_xpath("Data[@Name='TargetFilename']").text
        p = Process.EventIdEleven(pid,path,fileName)
        p.time = str(utc_to_asia_seoul(self.get_xpath("Data[@Name='UtcTime']").text))
        p.createTime = str(utc_to_asia_seoul(self.get_xpath("Data[@Name='CreationUtcTime']").text))
        return p
    
    def get_process_from_12_event(self):                                ##eventID12
        pid = int(self.get_xpath("Data[@Name='ProcessId']").text)
        path = self.get_xpath("Data[@Name='Image']").text
        eventType= self.get_xpath("Data[@Name='EventType']").text
        targetObject = self.get_xpath("Data[@Name='TargetObject']").text
        p=Process.EventIdTwelve(pid,path,eventType,targetObject)
        p.time = str(utc_to_asia_seoul(self.get_xpath("Data[@Name='UtcTime']").text))
        return p

    def get_process_from_13_event(self):                                ##eventID 13
        pid = int(self.get_xpath("Data[@Name='ProcessId']").text)
        path = self.get_xpath("Data[@Name='Image']").text
        eventType= self.get_xpath("Data[@Name='EventType']").text
        targetObject = self.get_xpath("Data[@Name='TargetObject']").text
        detail = self.get_xpath("Data[@Name='Details']").text
        p=Process.EventIdThirteen(pid,path,eventType,targetObject,detail)
        p.time = str(utc_to_asia_seoul(self.get_xpath("Data[@Name='UtcTime']").text))
        return p
    
    def get_process_from_14_event(self):                                ##eventID 13
        pid = int(self.get_xpath("Data[@Name='ProcessId']").text)
        path = self.get_xpath("Data[@Name='Image']").text
        targetObject = self.get_xpath("Data[@Name='TargetObject']").text
        newName = self.get_xpath("Data[@Name='NewName']").text
        p=Process.EventIdFourteen(pid,path,targetObject,newName)
        p.time = str(utc_to_asia_seoul(self.get_xpath("Data[@Name='UtcTime']").text))
        return p

    def get_process_from_22_event(self):
        pid = int(self.get_xpath("Data[@Name='ProcessId']").text)
        path = self.get_xpath("Data[@Name='Image']").text
        queryName = self.get_xpath("Data[@Name='QueryName']").text
        p = Process.EventIdTwentyTwo(pid,path,queryName)
        p.time = str(utc_to_asia_seoul(self.get_xpath("Data[@Name='UtcTime']").text))
        return p

    def get_process_from_event(self):
        if self.is_sysmon_proc_created_event():
            return self.get_process_from_1_event()
        elif self.is_sysmon_proc_exited_event():
            return self.get_process_from_5_event()
        elif self.is_sysmon_proc_network_connected_event():
            return self.get_process_from_3_event()
        elif self.is_sysmon_proc_create_remote_thread_event():
            return self.get_process_from_8_event()
        elif self.is_sysmon_proc_file_created_event():
            return self.get_process_from_11_event()
        elif self.is_sysmon_proc_registry_add_event():
            return self.get_process_from_12_event()
        elif self.is_sysmon_proc_registry_set_event():
            return self.get_process_from_13_event()
        elif self.is_sysmon_proc_registry_rename_event():
            return self.get_process_from_14_event()
        elif self.is_sysmon_proc_dns_event():
            return self.get_process_from_22_event()



        
