import re

class Rule():
    def __init__(self):
        self._RuleId = []
        self._RuleName = []
        self._Weight = []
        self._EventID = []
        self._EventDataName = []
        self._Expr = []
        self._Type = []

    @property
    def RuleId(self):
        return self._RuleId

    @property
    def RuleName(self):
        return self._RuleName

    @property
    def Weight(self):
        return self._Weight

    @property
    def EventID(self):
        return self._EventID

    @property
    def EventDataName(self):
        return self._EventDataName

    @property
    def Expr(self):
        return self._Expr

    @property
    def Type(self):
        return self._Type

    @RuleId.setter
    def RuleId(self, text):
        self._RuleId = text

    @RuleName.setter
    def RuleName(self, text):
        self._RuleName = text

    @Weight.setter
    def Weight(self, text):
        self._Weight = text

    @EventID.setter
    def EventID(self, text):
        self._EventID = text

    @EventDataName.setter
    def EventDataName(self, text):
        self._EventDataName = text

    @Expr.setter
    def Expr(self, text):
        self._Expr = text

    # def Expr(self, expr):
        # self._Expr = dict(expr[0])

    @Type.setter
    def Type(self, text):
        self._Type = text

    def __str__(self):
        return f"RuleId={self._RuleId}, RuleName={self._RuleName}, Weight={self._Weight}, EventID={self._EventID}, EventDataName={self._EventDataName}, Expr={self._Expr}, Type ={self._Type}"

    def scan(self, text):
        if self._Expr["type"] == "Regex":
            pattern = re.compile(self._Expr['expr'])
            m = pattern.search(text)
            if m is not None:
                return True
            else:
                return False
        elif self._Expr["type"] == "string":
            pattern = self._Expr['expr']
            if pattern in text:
                return True
            else:
                return False