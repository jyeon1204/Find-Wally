# import ProcessTree.Process as Process
# import ProcessTree.Node as n
# from ProcessTree.Entry import utc_to_asia_seoul

#  set If the parent process does not exist
from src.core.Sysmon.ProcessTree import Process
from src.core.Sysmon.ProcessTree.Entry import utc_to_asia_seoul
import src.core.Sysmon.ProcessTree.Node as n


def create_fake_parent_process(pid, name,time):
    p = Process.EventIdOneFive(pid, 0, "UNKNOWN", name, "UNKNOWN","UNKNOWN")
    p.notes = Process.EventIdOneFive.NOTE_FAKE_PARENT
    p.begin=time
    return p
    
def create_fake_process(pid,path,time):
    p = Process.EventIdOneFive(pid, 0, "UNKNOWN", "UNKNOWN", path,"UNKNOWN")
    p.begin =time
    p.notes = Process.EventIdOneFive.NOTE_FAKE_PROCESS
    return p

class ProcessTreeAnalyzer():
    def __init__(self):
        self._defs={}
        self._roots=[]
    
    def analyze(self, entries):
        """
        @type entries: iterable of Entry
        """
        open_processes = {}
        closed_processes = []
        action_processes =[]
        for entry in entries:
            if entry.is_sysmon_proc_created_event():
                process = entry.get_process_from_event()
                if process.pid in open_processes:
                    other = open_processes[process.pid]
                    other.notes = process.NOTE_END_LOST
                    closed_processes.append(other)
                open_processes[process.pid] = process

                if process.ppid in open_processes:
                    process.parent = open_processes[process.ppid]
                    process.parent.children.append(process)
                else:
                    # open a faked parent
                    process.parent = create_fake_parent_process(process.ppid, process.ppname,process.begin)
                    process.parent.children.append(process)
                    open_processes[process.ppid] = process.parent

            elif entry.is_sysmon_proc_exited_event():
                process = entry.get_process_from_event()
                if process.pid in open_processes:
                    # use existing process instance, if it exists
                    existing_process = open_processes[process.pid]
                    if existing_process.notes == process.NOTE_FAKE_PARENT:
                        # if we faked it, have to be careful not to lose the children
                        process.children = existing_process.children
                        # discard the faked entry, cause we'll have better info now
                    else:
                        process = existing_process
                    process.end = str(utc_to_asia_seoul(entry.get_xpath("Data[@Name='UtcTime']").text))
                    del(open_processes[process.pid])
                    closed_processes.append(process)
                else:
                    # won't be able to guess parent, since it's PID may have been recycled
                    closed_processes.append(process)
            elif entry.is_sysmon_proc():
                process = entry.get_process_from_event()
                if process.pid in open_processes :
                    existing_process = open_processes[process.pid]
                    existing_process.action.append(process)
                else:
                    try:
                        time = process.begin
                    except :
                        time = process.time
                    fake_process = create_fake_process(process.pid,process.Image,time)
                    fake_process.action.append(process)
                    open_processes[fake_process.pid]=fake_process
                action_processes.append(process)

        i = 0
        for process_set in [open_processes.values(), closed_processes]:
            for process in process_set:
                process.id = i
                i += 1
                self._defs[process.id] = process
                if process.parent is None:
                    self._roots.append(process.id)
            
        for process in action_processes:
            process.id = i
            i+=1
            self._defs[process.id] = process

        for process in self._defs.values():
            if type(process).__name__ == "EventIdOneFive" : 
                if process.parent is not None:
                    process.parent = process.parent.id
                process.children = [c.id for c in process.children]
                process.action = [c.id for c in process.action]

    def get_roots(self):
        """
        @rtype: list of Node
        """
        ret = []
        for root in self._roots:
            if root is None:
                continue
            ret.append(n.Node(root, None, n.get_children_nodes(self, root)))
        return ret

    def get_process(self, id):
        return self._defs[id]
    
    def get_action(self,id):
        return list([self._defs[i] for i in self._defs[id].action])
