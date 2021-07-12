# -*- coding: utf-8 -*-
import sys
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import json

def connectmain():
    global count
    count += 1

#Main_frame에서 실행시킬 때
# file_name = ""
#EventLogAnalysis_frame에서 실행시킬 때
file_name = "2020-11-11 16.48.36.489000"
def getdir(data):
    global file_name
    file_name = data
    return file_name

#PS 데이터
def fileopen(filename):
    f = open(".\detected\\" + filename + "\\ps.json", 'r')
    file = json.load(f)
    data = list(file)
    P0_Image = [[], [], []]; P0_Pid = [[], [], []]; action = [[], [], []];
    type = [[], [], []]; level = [[], [], []]; Time = [[], [], []];
    PName = [[], [], []]

    for i in range(len(data)):
        P0_Image[i].append((data[i]['0'][0]['Image']))
        P0_Pid[i].append((data[i]['0'][0]['Pid']))
        level[i].append(0)
        Time[i].append((data[i]['0'][0]['Time']))
        PName[i].append((data[i]['0'][0]['Process Name']))
        try:
            for j in range(len(data[i]['0'][0]['1'][0])):
                P0_Image[i].append((data[i]['0'][0]['1'][j]['Image']))
                P0_Pid[i].append((data[i]['0'][0]['1'][j]['Pid']))
                level[i].append(1)
                Time[i].append((data[i]['0'][0]['1'][j]['Time']))
                PName[i].append((data[i]['0'][0]['1'][j]['Process Name']))
                try:
                    for k in range(len(data[i]['0'][0]['1'][j])):
                        P0_Image[i].append((data[i]['0'][0]['1'][j]['2'][k]['Image']))
                        P0_Pid[i].append((data[i]['0'][0]['1'][j]['2'][k]['Pid']))
                        level[i].append(2)
                        Time[i].append((data[i]['0'][0]['1'][j]['2'][k]['Time']))
                        PName[i].append((data[i]['0'][0]['1'][j]['2'][k]['Process Name']))
                        try:
                            for p in range(len(data[i]['0'][0]['1'][j]['2'][k])):
                                P0_Image[i].append((data[i]['0'][0]['1'][j]['2'][k]['3'][p]['Image']))
                                P0_Pid[i].append((data[i]['0'][0]['1'][j]['2'][k]['3'][p]['Pid']))
                                level[i].append(3)
                                Time[i].append((data[i]['0'][0]['1'][j]['2'][k]['3'][p]['Time']))
                                PName[i].append((data[i]['0'][0]['1'][j]['2'][k]['3'][p]['Process Name']))
                        except:
                            pass
                except:
                    pass
        except:
            pass

    detected = [[], []]
    with open(".\detected\\" + file_name + "\\detectedProcess.json")as json_file:
        detected_data = json.load(json_file)
        for detect in detected_data:
            detected[0].append(detect['ActionIndex']) # deteted 된 PID 넘버
            detected[1].append(detect['RuleId'])  # detected 된 RuleID

    Ruledata = [[], []]
    with open("..\\core\\Sysmon\\ProcessTree\\Rule\\EventId.json", "r", encoding="utf-8")as json_file:
        rule_data = json.load(json_file)
        for ruleid in rule_data:
            Ruledata[0].append(ruleid['RuleId'])
            Ruledata[1].append(ruleid['RuleName'])

    return P0_Image, P0_Pid, action, type, level, detected,Ruledata, data, Time, PName

#액션
def openaction():
    # Taction : 트리 몇 레벨에 action이 있는지
    Taction0 = [[], [], []]; Taction1 = [[], [], []]; Taction2 = [[], [], []]; Taction3 = [[], [], []]
    Iaction0 = [[], [], []]; Iaction1 = [[], [], []]; Iaction2 = [[], [], []]; Iaction3 = [[], [], []]
    Alevel = [[], [], []]
    with open(".\detected\\" + file_name + "\\detectedAction.json", 'r') as f:
        file = json.load(f)
        data = list(file)
        for i in range(len(data)):
            try:
                for j in range(len(data[i]['0'][0]['action'])):  # 0번액션
                    Taction0[i].append(data[i]['0'][0]['action'][j]['Type'])
                    Iaction0[i].append(data[i]['0'][0]['action'][j]['Image'])
                    Alevel[i].append(0)
                try:
                    for k in range(len(data[i]['0'][0]['1'][0]['action'])):  # 1번액션
                        Taction1[i].append(data[i]['0'][0]['1'][0]['action'][k]["Type"])
                        Iaction1[i].append(data[i]['0'][0]['1'][0]['action'][k]["Image"])
                        Alevel[i].append(1)
                    try:
                        for l in range(len(data[i]['0'][0]['1'][0]['2'])):  # 2번액션
                            Taction2[i].append(data[i]['0'][0]['1'][0]['2'][0]["action"][0]['Type'])
                            Iaction2[i].append(data[i]['0'][0]['1'][0]['2'][0]["action"][0]['Image'])
                            Alevel[i].append(2)
                        try:
                            for t in range(len(data[i]['0'][0]['1'][0]['2'])):  # 3번액션
                                Taction3[i].append(data[i]['0'][0]['1'][0]['2'][0]["3"][0]['action'][0]['Type'])
                                Iaction3[i].append(data[i]['0'][0]['1'][0]['2'][0]["3"][0]['action'][0]['Image'])
                                Alevel[i].append(3)
                        except:
                            pass
                    except:
                        pass
                except:
                    pass
            except:
                pass
    return Taction0, Taction1, Taction2, Taction3, Iaction0, Iaction1, Iaction2, Iaction3, Alevel

class StWidgetForm(QGroupBox):
    # 위젯 베이스 클래스
    def __init__(self):
        QGroupBox.__init__(self)
        self.box = QBoxLayout(QBoxLayout.TopToBottom)
        self.setLayout(self.box)

class Sysmon_graph(StWidgetForm):
    # main의 그래프 창에 띄울거 작성
    def __init__(self):
        super(Sysmon_graph, self).__init__()
        self.setStyleSheet("border: 0px")
        self.initUI()

    def initUI(self):
        self.fig = plt.Figure()
        self.fig.clear()
        filename = getdir(file_name)
        name = []
        count = []
        with open(".\detected\\"+filename+"\\graph.json")as json_file:
            json_data = json.load(json_file)
            for data in json_data:
                name.append(data['name'][11:19])
                count.append(data['count'])

        ind = np.arange(len(name))
        width = 0.35

        ax = self.fig.add_subplot(111)
        ax.bar(ind, count, width)
        ax.set_xticks(ind + width / 20)
        # ax.set_xticklabels(rotation=70) #글씨 70도 각도 기울임
        ax.set_xticklabels(name)
        # ax.legend()

        self.canvas = FigureCanvas(self.fig)
        self.canvas.draw()
        self.box.addWidget(self.canvas)

class Model(QStandardItemModel):
    # 사용자 데이터 모델 설정
    # [{"type":str, "objects":[str, ...]}, ...]
    # 위의 데이터 형식을 이용하여 서브 아이템을 가지는 모델을 생성
    def __init__(self, data):
        QStandardItemModel.__init__(self)

class Tree(StWidgetForm):
    def __init__(self,num):
        self.num = num
        super(Tree, self).__init__()
        self.setStyleSheet("border: 0px")
        self.initUI()

    def initUI(self):
        self.tfunction()

    def tfunction(self):
        QTW = QTreeWidget()
        QTW.setAlternatingRowColors(True)
        QTW.header().setVisible(False)
        itemA = QTreeWidgetItem(QTW)
        Taction0, Taction1, Taction2, Taction3, Iaction0, Iaction1, Iaction2, Iaction3, Alevel = openaction()
        P0_Image, P0_Pid, action, type, level, detected, Ruledata, data, Time, PName = fileopen(file_name)
        for k in range(len(level[self.num])):
            if level[self.num][k] == 0:
                itemA.setText(0, P0_Image[self.num][k])
                for i in range(len(Taction0[self.num])):
                    itemAa = QTreeWidgetItem(itemA)
                    itemAa.setText(0, "[Action] " + Taction0[self.num][i] + " : (" + Iaction0[self.num][i] + ")")
                    if P0_Pid[self.num][k] in detected[0]:
                        itemAa.setForeground(0, QBrush(QColor("red")))
                if P0_Pid[self.num][k] in detected[0]:
                    itemA.setForeground(0, QBrush(QColor("red")))
            elif level[self.num][k] == 1:
                itemB = QTreeWidgetItem(itemA)
                itemB.setText(0, P0_Image[self.num][k])
                for i in range(len(Taction1[self.num])):
                    itemBb = QTreeWidgetItem(itemB)
                    itemBb.setText(0, "[Action] " + Taction1[self.num][i] + " : (" + Iaction1[self.num][i] + ")")
                    if P0_Pid[self.num][k] in detected[0]:
                        itemBb.setForeground(0, QBrush(QColor("red")))
                if P0_Pid[self.num][k] in detected[0]:
                    itemB.setForeground(0, QBrush(QColor("red")))
            elif level[self.num][k] == 2:
                itemC = QTreeWidgetItem(itemB)
                itemC.setText(0, P0_Image[self.num][k])
                for i in range(len(Taction2[self.num])):
                    itemCc = QTreeWidgetItem(itemC)
                    itemCc.setText(0, "[Action] " + Taction2[self.num][i] + " : (" + Iaction2[self.num][i] + ")")
                    if P0_Pid[self.num][k] in detected[0]:
                        itemCc.setForeground(0, QBrush(QColor("red")))
                if P0_Pid[self.num][k] in detected[0]:
                    itemC.setForeground(0, QBrush(QColor("red")))
            elif level[self.num][k] == 3:
                itemD = QTreeWidgetItem(itemC)
                itemD.setText(0, P0_Image[self.num][k])
                for i in range(len(Taction3[self.num])):
                    itemDd = QTreeWidgetItem(itemD)
                    itemDd.setText(0, "[Action] " + Taction3[self.num][i] + " : (" + Iaction3[self.num][i] + ")")
                    if P0_Pid[self.num][k] in detected[0]:
                        itemDd.setForeground(0, QBrush(QColor("red")))
                if P0_Pid[self.num][k] in detected[0]:
                    itemD.setForeground(0, QBrush(QColor("red")))
        self.box.addWidget(QTW, alignment=Qt.AlignVCenter)

class Root1_tree(StWidgetForm):
    def __init__(self):
        super(Root1_tree, self).__init__()
        self.setStyleSheet("border: 0px")
        self.initUI()

    def initUI(self):
        layout_main = QVBoxLayout()
        self.box.addLayout(layout_main)
        layout_main.addWidget(Tree(0))
        layout_main.addWidget(Tree(1))
        layout_main.addWidget(Tree(2))

class Sysmon_tree(StWidgetForm):
    # main의 tree구조 창에 띄울거 작성
    def __init__(self):
        super(Sysmon_tree, self).__init__()
        self.initUI()

    def initUI(self):
        layout_main = QVBoxLayout()
        self.box.addLayout(layout_main)
        self.setStyleSheet("background-color: #FFFFF;")
        self.setStyleSheet("border: 10px")

        tabs = QTabWidget()
        tabs.addTab(Root1_tree(), 'tree')
        tabs.setMinimumHeight(500)
        tabs.setMinimumWidth(1000)
        tabs.setMaximumHeight(500)
        tabs.setMaximumWidth(1000)
        scrollarea = QScrollArea()
        scrollarea.setWidget(tabs)
        layout_main.addWidget(scrollarea)


class Root(StWidgetForm):
    def __init__(self,num):
        self.num = num
        super(Root, self).__init__()
        self.initUI()

    def initUI(self):
        self.function()

    def function(self):
        List = ["PID", "Process Name", "Time", "Path", "Rulename"]
        P0_Image, P0_Pid, action, type, level, detected, Ruledata, data, Time, PName = fileopen(file_name)
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(List)

        table.setColumnWidth(0, 80)
        table.setColumnWidth(1, 130)
        table.setColumnWidth(2, 220)
        table.setColumnWidth(3, 470)
        table.setColumnWidth(4, 230)
        table.setRowCount(len(P0_Image[self.num]))

        for i in range(len(P0_Image[self.num])):
            table.setItem(i, 3, QTableWidgetItem(str(P0_Image[self.num][i])))
            table.setItem(i, 2, QTableWidgetItem(str(Time[self.num][i])))
            table.setItem(i, 1, QTableWidgetItem(str(PName[self.num][i])))
            i = i + 1

        for i in range(len(P0_Pid[self.num])):
            table.setItem(i, 0, QTableWidgetItem(str(P0_Pid[self.num][i])))
            tabledata = []
            tabledata.append(str(P0_Pid[self.num][i]))
            for k in range(len(tabledata)):
                for p in range(len(detected[0])):
                    if int(tabledata[k]) == int(detected[0][p]):  #액션 인덱스
                        for j in range(len(Ruledata[0])):
                            if detected[1][p] == Ruledata[0][j]:
                                table.setItem(i, 4, QTableWidgetItem(str(Ruledata[1][j])))
            i = i + 1

        table.setMinimumHeight(440)
        table.setMinimumWidth(730)
        table.setMaximumHeight(440)
        table.setMaximumWidth(730)

        self.box.addWidget(table, alignment=Qt.AlignVCenter | Qt.AlignVCenter)

class Root1(StWidgetForm):
    def __init__(self):
        super(Root1, self).__init__()
        self.setStyleSheet("border: 0px")
        self.initUI()

    def initUI(self):
        layout_main = QVBoxLayout()
        self.box.addLayout(layout_main)
        layout_main.addWidget(Root(0))

class Root2(StWidgetForm):
    def __init__(self):
        super(Root2, self).__init__()
        self.setStyleSheet("border: 0px")
        self.initUI()

    def initUI(self):
        layout_main = QVBoxLayout()
        self.box.addLayout(layout_main)
        layout_main.addWidget(Root(1))

class Root3(StWidgetForm):
    def __init__(self):
        super(Root3, self).__init__()
        self.setStyleSheet("border: 0px")
        self.initUI()

    def initUI(self):
        layout_main = QVBoxLayout()
        self.box.addLayout(layout_main)
        layout_main.addWidget(Root(2))

class forRoot(StWidgetForm):
    def __init__(self,num):
        super(forRoot, self).__init__()
        self.setStyleSheet("border: 0px")
        self.initUI(num)

    def initUI(self,num):
        layout_main = QVBoxLayout()
        self.box.addLayout(layout_main)
        layout_main.addWidget(Root(num))

class Sysmon_table(StWidgetForm):
    def __init__(self):
        super(Sysmon_table, self).__init__()
        self.initUI()

    def initUI(self):
        List = ["PID", "Process Name", "Type", "Rule Name"]
        P0_Image, P0_Pid, action, type, level, detected, Ruledata, data, Time, PName = fileopen(file_name)
        layout_main = QHBoxLayout()
        self.box.addLayout(layout_main)
        self.setStyleSheet("border: 10px")

        tabs = QTabWidget()
        tabs.setStyleSheet("background-color: #FFFFFF")
        for i in range(len(data)):
            tabs.addTab(forRoot(i), data[i]['0'][0]['Image'])

        # scrollarea = QScrollArea()
        # scrollarea.setWidget(tabs)
        # layout_main.addWidget(scrollarea)

        layout_main.addWidget(tabs)


class Sysmon_under(StWidgetForm):
    def __init__(self):
        super(Sysmon_under, self).__init__()
        self.initUI()

    def initUI(self):
        layout_main = QHBoxLayout()
        self.box.addLayout(layout_main)
        self.setStyleSheet("border: 0px")

        sysgraph = Sysmon_tree()
        layout_main.addWidget(sysgraph)
        sysgraph.setStyleSheet(
            "border-style: solid;"
            "border-width: 1px;"
            "border-color: #AAAAAA;"
        )

        systable = Sysmon_table()
        layout_main.addWidget(systable)
        systable.setStyleSheet(
            "border-style: solid;"
            "border-width: 1px;"
            "border-color: #AAAAAA;"
        )

        #테이블 큰틀
        systable.setMinimumWidth(800)
        systable.setMinimumHeight(529)
        systable.setMaximumHeight(529)
        systable.setMaximumWidth(800)


class Sys_main(StWidgetForm):
    def __init__(self):
        super(Sys_main, self).__init__()
        self.setStyleSheet("background-color: white")
        self.setGeometry(150, 120, 1400, 900)
        self.setFixedWidth(1400)
        self.setFixedHeight(900)
        self.initUI()

    def initUI(self):
        # 상단바, 기존 화면 레이아웃 생성 및 추가
        layout_bar = QHBoxLayout()
        layout_main = QVBoxLayout()
        layout_top = QHBoxLayout()
        layout_bottom = QHBoxLayout()
        self.box.addLayout(layout_bar)
        self.box.addLayout(layout_main)
        layout_main.addLayout(layout_top)
        layout_main.addLayout(layout_bottom)
        layout_main.addLayout(layout_bar)

        # 상단 이전 버튼 생성 및 부착
        label1 = QPushButton('탐지 시간 : '+ file_name[:20])
        label1.setFont(QFont('나눔고딕', 12, QFont.Bold))
        label1.setMinimumWidth(400)
        label1.setMinimumHeight(50)
        label1.setMaximumWidth(400)
        label1.setMaximumHeight(50)
        label1.setStyleSheet(
            "border-width: 1px;"
            "border-color: #000000;"
            "border-radius: 3px")
        layout_bar.addWidget(label1, alignment=Qt.AlignLeft)

        # 그래프, 트리 출력 창 부착
        graphwid = Sysmon_graph()
        graphwid.setMinimumHeight(300)
        graphwid.setMaximumHeight(300)
        layout_top.addWidget(graphwid)

        treewid = Sysmon_under()
        treewid.setMinimumHeight(550)
        treewid.setMaximumHeight(550)
        layout_bottom.addWidget(treewid)


class MyApp(QMainWindow, QWidget):
    # 크기 및 출력 위치를 변경
    def __init__(self):
        super().__init__()
        self.stk_w = QStackedWidget(self)
        # self.setGeometry(150, 120, 1400, 900)
        # self.setFixedWidth(1400)
        # self.setFixedHeight(900)
        self.initUI()

    def initUI(self):
        # 레이아웃 시작

        # 레이아웃 생성
        wid = QWidget(self)
        self.setCentralWidget(wid)
        layout1 = QVBoxLayout()

        # AMSI 메인 창 부착
        layout1.addWidget(Sys_main())

        wid.setLayout(layout1)
        layout1.addWidget(Sysmon_graph())
        self.setWindowTitle('Find Wally')
        self.show()


if __name__ == '__main__':  # 큐티파이는 반드시 어플리케이션 오브젝트을 생성해야만 함.
    app = QApplication(sys.argv)  # sys.argv는 파이썬으로 쉘 스크립트
    ex = MyApp()  # 내가 만든 창에 넣을 객체 생성
    sys.exit(app.exec_())  # 이벤트 처리를 위한 메인 루프 실행, 메인루프가 끝날때 exit가 실행됨.