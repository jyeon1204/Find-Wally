# from ProcessTree.Xml import *
# from ProcessTree.ProcessTree import Tree
# from ProcessTree.Entry import get_entreis
# from ProcessTree.ProcessTree import dict_tree
# from ProcessTree.ProcessTreeAnalyzer import ProcessTreeAnalyzer
# from ProcessTree.Rule.DetectProcess import *
# from ProcessTree.Rule.RuleSet import *
import json

from src.core.Sysmon.ProcessTree.Entry import get_entreis
from src.core.Sysmon.ProcessTree.ProcessTree import Tree, dict_tree
from src.core.Sysmon.ProcessTree.ProcessTreeAnalyzer import ProcessTreeAnalyzer
from src.core.Sysmon.ProcessTree.Rule.DetectProcess import detect_process, detect_action
from src.core.Sysmon.ProcessTree.Rule.RuleSet import RuleSet
from src.core.Sysmon.ProcessTree.Xml import count_timestamp, parse_xml


def abc():
    ### Add Rules into Rule()
    rulelistOne = list()
    rulePath = "..\\..\\src\\core\\Sysmon\\ProcessTree\\Rule\\RuleEventIdOneFive.json"
    r = RuleSet()
    rulelistOne = r.addrule(rulePath)

    rulelistElse = list()
    rulePath = "..\\..\\src\\core\\Sysmon\\ProcessTree\\Rule\\RuleEventIdThree.json"
    r = RuleSet()
    rulelistElse = r.addrule(rulePath)
    print('rule end')

    ### Load Events & Prepare to make Process Tree
    filename = '.\\event_tmp.xml'
    analyzer = ProcessTreeAnalyzer()
    xml_node = parse_xml(filename)
    path = count_timestamp(xml_node)
    analyzer.analyze(get_entreis(xml_node))
    print('analyzer end')
    T=[]
    TIndex = []
    TIndex_tmp = []
    for root in analyzer.get_roots():
        # print(root)
        T.append(Tree(root))
        T[-1].set_process(T[-1].root, analyzer)


    ## Detect Process by Rule
    res = []
    for tree in T:
        for pro in tree.p:                      # detect process - EventIdOneFive
            detected = detect_process(pro, rulelistOne)
            if detected != None :
                TIndex_tmp.append(T.index(tree))    # ~49 중복제거하여 탐지된 Tree 리스트 생성
                for v in TIndex_tmp:
                    if v not in TIndex:
                        TIndex.append(v)
                res.append({"RuleId": detected, "TreeIndex": TIndex.index(T.index(tree)), "ActionIndex": pro.pid})
    
    with open(path+"\\detectedProcess.json","w") as f:
        json.dump(res,f,indent=2)

    ### 탐지된 Tree 형태를 순서대로 리스트에 모음
    dT = []
    for ii in TIndex:
        dT.append(T[ii])
        
    d_json = []
    for i in dT:
        tmp = {}
        dict_tree(i.root,analyzer,tmp,indent=0)
        d_json.append(tmp)

    with open(path+"\\ps.json","w") as f:
        json.dump(d_json,f,indent=2)

    res = []
    for tree in dT:
        for act_class in tree.a :               # detect action - EventIdElse
            for act in act_class :
                detected = detect_action(act, rulelistElse)
                if detected != None :
                    res.append({"RuleId": detected, "TreeIndex": dT.index(tree), "ActionIndex": act_class.index(act)})
    with open(path+"\\detectedAction.json","w") as f:
        json.dump(d_json,f,indent=2)
