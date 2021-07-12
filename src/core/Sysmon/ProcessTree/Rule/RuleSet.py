from .Rule import Rule
import json

class RuleSet:
    def __init__(self):
        self.listrule = list()

    def addrule(self, path):
        with open(path, "r", encoding="utf-8") as json_file:
            json_data = json.load(json_file)
            for data in json_data:
                r = Rule()
                r.RuleId = data['RuleId']
                r.RuleName = data['RuleName']
                r.Weight = data['Weight']
                r.EventID = data['Rule']['EventID']
                r.EventDataName = data['Rule']['EventDataName']
                r.Expr = data['Rule']['Expr']
                r.Type = data['Rule']['Type']
                self.listrule.append(r)
            return self.listrule

    def scan(self, dic):
        detect = []
        for i in dic:
            tmp = []
            for r in self.listrule:
                t = r.scan(i)
                if t:
                    s = {i: dic[i]}
                    tmp.append(s)
                    tmp.append(r)
                    detect.append(tmp)
                    break
        return detect