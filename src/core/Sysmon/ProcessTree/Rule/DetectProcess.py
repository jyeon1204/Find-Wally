# DetectProcess.py
# from ProcessTree.ProcessTree import *
import json
import re

class DetectProcess():
    def __init__(self, EventId):
        self.EventId = EventId

    def print_json(self):
        return self

def detect_process(p, rulelist):
    for ruleCount in rulelist:
        RuleId = ruleCount.RuleId
        EventID = ruleCount.EventID
        EventDataName = ruleCount.EventDataName
        Expr = ruleCount.Expr
        RuleType = ruleCount.Type
        # print(RuleId, p)
        # print(EventDataName)
        if EventDataName == "ParentImage":
            if p.parent:
                pp = p.parent
                EventDataName = "Image"
                result = detect_hit_p(pp, Expr, EventDataName, RuleId, RuleType)
                if result != None:
                    return result
        elif EventDataName == "ParentCommandLine":
            if p.parent:
                pp = p.parent
                EventDataName = "CommandLine"
                result = detect_hit_p(pp, Expr, EventDataName, RuleId, RuleType)
                if result != None:
                    return result
        else:
            result = detect_hit_p(p, Expr, EventDataName, RuleId, RuleType)
            if result != None:
                return result


def detect_action(a, rulelist):
    for ruleCount in rulelist:
        RuleId = ruleCount.RuleId
        EventID = ruleCount.EventID
        EventDataName = ruleCount.EventDataName
        Expr = ruleCount.Expr
        RuleType = ruleCount.Type
        if EventID in str(type(a)):
            result = detect_hit_a(a, Expr, EventDataName, RuleId, RuleType)
            if result != None:
                return result

def detect_hit_p(p, Expr, EventDataName, RuleId, RuleType):
    # print(">>>" + str(p))
    # print(type(p))
    # print(EventDataName)
    if EventDataName == "Image":
        if Expr in eval("p." + EventDataName):
            return RuleId
    else:
        if Expr == eval("p." + EventDataName):
            return RuleId

def detect_hit_a(a, Expr, EventDataName, RuleId, RuleType):
    if EventDataName == "Image":
        if Expr in eval("a." + EventDataName):
            return RuleId
    elif EventDataName == "FileName":
        if Expr in eval("a." + EventDataName):
            return RuleId
    else:
        if Expr == eval("a." + EventDataName):
            return RuleId



