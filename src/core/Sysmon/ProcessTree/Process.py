##Information by Process
from datetime import datetime

class EventIdOneFive():
    NOTE_FAKE_PARENT = "Fake Parent: This is a faked process created since a ppid didn't exist"
    NOTE_END_LOST = "Lost End Timestamp: This end timestamp is suspect, because it collided with another process"
    NOTE_FAKE_PROCESS = "Fack Process : This is a faked process created sine a pid didn't exist"
    def __init__(self, pid, ppid, cmdline, ppname, path, OriginalFileName):
        self.pid = pid
        self.ppid = ppid
        self.path = path
        self.OriginalFileName = OriginalFileName
        self.CommandLine = cmdline
        self.ppname = ppname
        self.begin = datetime.min
        self.end = datetime.min
        self.parent = None
        self.children = []
        self.action = []
        self.Image = path
        self.notes = None
        self.id = None  # set by analyzer, unique with analyzer session
    
    def __str__(self):
        return f"{self.path}, CommandLine={self.CommandLine}, pid={self.pid}, ppid={self.ppid}, begin ={self.begin}, end ={self.end}, note={self.notes}, OriginalFileName={self.OriginalFileName} "
        

class EventIdThree():
    def __init__(self,pid,protocal,srcip,srcport,dstip,dstprot,path):
        self.pid = pid
        self.Image = path
        self.protocal = protocal
        self.SourceIp = srcip
        self.SourcePort = srcport
        self.DestinationIp = dstip
        self.DestinationPort = dstprot
        self.time = datetime.min
        self.id = None  # set by analyzer, unique with analyzer session

    def info(self):
        tmp = {}
        tmp["Image"] = self.Image
        tmp["pid"] = self.pid
        tmp["Time"] = self.time
        tmp["Type"] = "Network connection"
        return tmp

    def __str__(self):
        return f"{self.Image}, pid={self.pid}, protocal={self.protocal}, srcip={self.srcip}, srcport={self.srcport} ,dstip={self.dstip}, dstport={self.dstport}"

class EventIdEight():
    def __init__(self,pid,path,dstpid,dstpath,address,module,fuction):
        self.pid = pid                  #Source pid in the sysmon event data, Set name as pid for ease of development
        self.Image = path             #Source path in the sysmon event data, Set name as path for ease of development
        self.dstpid = dstpid
        self.dstpath = dstpath
        self.startAddress = address
        self.startModule = module
        self.startFuction = fuction
        self.time = datetime.min
        self.id = None  # set by analyzer, unique with analyzer session

    def info(self):
        tmp = {}
        tmp["Image"] = self.Image
        tmp["pid"] = self.pid
        tmp["Time"] = self.time
        tmp["Type"] = "CreateRemoteThread"
        return tmp

    def __str__(self):
        return f"{self.Image}, srcpid={self.pid},dstpid={self.dstpid}, dstpath={self.dstpath}, startAddress={self.startAddress}, startModule={self.startModule}, startFuction={self.startFuction}"

class EventIdEleven():
    def __init__(self,pid,path,FileName):
        self.pid = pid
        self.Image = path
        self.FileName = FileName
        self.time = datetime.min
        self.createTime = datetime.min
        self.id = None # set by analyzer, unique with analyzer session

    def info(self):
        tmp = {}
        tmp["Image"] = self.Image
        tmp["pid"] = self.pid
        tmp["Time"] = self.time
        tmp["Type"] = "File Create"
        return tmp

    def __str__(self):
        return f"{self.Image},FileName={self.FileName},creatTime={self.createTime}"

class EventIdTwelve():
    def __init__(self,pid,path,eventType,TargetObject):
        self.pid = pid
        self.Image = path
        self.eventType = eventType
        self.TargetObject = TargetObject
        self.time = datetime.min
        self.id = None

    def info(self):
        tmp = {}
        tmp["Image"] = self.Image
        tmp["pid"] = self.pid
        tmp["Time"] = self.time
        tmp["Type"] = "RegistryEvent(Object create and delete)"
        return tmp

    def __str__(self):
        return f"{self.Image},eventType={self.eventType},TargetObject={self.TargetObject}"

class EventIdThirteen():
    def __init__(self,pid,path,eventType,targetObject,detail):
        self.pid = pid
        self.Image = path
        self.eventType = eventType
        self.targetObject = targetObject
        self.time = datetime.min
        self.detail = detail
        self.id = None

    def info(self):
        tmp = {}
        tmp["Image"] = self.Image
        tmp["pid"] = self.pid
        tmp["Time"] = self.time
        tmp["Type"] = "RegistryEvent(Value Set)"
        return tmp

    def __str__(self):
        return f"{self.Image},eventType={self.eventType},targetObject={self.targetObject}, detail = {self.detail}"

class EventIdFourteen():
    def __init__(self,pid,path,targetObject,newName):
        self.pid = pid
        self.Image = path
        self.targetObject = targetObject
        self.time = datetime.min
        self.newName = newName
        self.id = None

    def info(self):
        tmp = {}
        tmp["Image"] = self.Image
        tmp["pid"] = self.pid
        tmp["Time"] = self.time
        tmp["Type"] = "RegistryEvent(Key and Value Rename)"
        return tmp

    def __str__(self):
        return f"{self.Image},eventType={self.eventType},targetObject={self.targetObject}, newName = {self.newName}"

class EventIdTwentyTwo():
    def __init__(self,pid,path,queryName):
        self.pid=pid
        self.Image=path
        self.queryName = queryName
        self.time = datetime.min
        self.id=None

    def info(self):
        tmp = {}
        tmp["Image"] = self.Image
        tmp["pid"] = self.pid
        tmp["Time"] = self.time
        tmp["Type"]="DNSEvent (DNS query)"
        return tmp

    def __str__(self):
        return f"{self.Image},queryName={self.queryName},time={self.time}"