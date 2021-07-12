class Tree():
    def __init__(self,root):
        self.root = root
        self.p=[]
        self.a=[] 
        self.n=[]
    
    def __str__(self):
        return str(self.root)

    def set_process(self,node,anlyzer):
        p = node.get_process(anlyzer)
        a = node.get_action(anlyzer)
        if p.parent:
            p.parent = anlyzer.get_process(p.parent)
        self.p.append(p)
        self.a.append(a)
        for children in node.get_children():
            self.n.append(children)
            self.set_process(children,anlyzer)
        return p,a
    

def dict_tree(node,anlyzer,x,indent =0):
    p = node.get_process(anlyzer)
    actions=[]
    for i in node.get_action(anlyzer):
        actions.append(i.info())
    res = list({action['Type']:action for action in actions}.values())
    try :
        x[indent].append({"Process Name": p.OriginalFileName,"Image":p.Image,"Pid":p.pid,"Time":str(p.begin),"action":res})

    except:
        x[indent] = [{"Process Name": p.OriginalFileName,"Image":p.Image,"Pid":p.pid,"Time":str(p.begin),"action":res}]

    for children in node.get_children():
        dict_tree(children,anlyzer,x[indent][len(x[indent])-1],indent=indent+1)
##원하는 함수 말해주세요