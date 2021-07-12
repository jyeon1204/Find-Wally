import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import json


imageinfo_data = dict()
pstree_data= dict()
psxview_data= dict()
hivelist_data= dict()
printkey_data= dict()
netscan_data= dict()
result_data= dict()
def Memory_JSON(dirname):
    # dirname = "20201121-185518"
    print("Memory_JSON : ", dirname)
    with open('..\\..\\program\\volatility\\' + dirname + '\\imageinfo_data.json', "r") as imageinfo_file:
        global imageinfo_data
        imageinfo_data = dict(json.load(imageinfo_file))
    with open('..\\..\\program\\volatility\\' + dirname + '\\pstree.json', "r") as pstree_file:
        global pstree_data
        pstree_data = json.load(pstree_file)
    with open('..\\..\\program\\volatility\\' + dirname + '\\psxview_process.json') as psxview_file:
        global psxview_data
        psxview_data = json.load(psxview_file)
    with open('..\\..\\program\\volatility\\' + dirname + '\\hivelist.json', "r") as hivelist_file:
        global hivelist_data
        hivelist_data = dict(json.load(hivelist_file))
    with open('..\\..\\program\\volatility\\' + dirname + '\\printkey_Run_process.json', "r") as printkey_file:
        global printkey_data
        printkey_data = dict(json.load(printkey_file))
    with open('..\\..\\program\\volatility\\' + dirname + '\\netscan_process.json', "r") as netscan_file:
        global netscan_data
        netscan_data = json.load(netscan_file)
    with open('..\\..\\program\\volatility\\' + dirname + '\\Result_hit_process.json', "r") as result_file:
        global result_data
        result_data = json.load(result_file)
    with open('..\\..\\program\\volatility\\' + dirname + '\\Result_hit_registry.json', "r") as result_file:
        global result_reg_data
        result_reg_data = json.load(result_file)


class StWidgetForm(QGroupBox):
    """
    위젯 베이스 클래스
    """

    def __init__(self):
        QGroupBox.__init__(self)
        self.box = QBoxLayout(QBoxLayout.TopToBottom)
        self.setLayout(self.box)

class Layout_Process(StWidgetForm):
    """
    Ps Tree 탭
    """

    def __init__(self):
        super(Layout_Process, self).__init__()
        self.setStyleSheet("border: 0px")
        self.initUI()

    def initUI(self):
        # QTreeView 생성 및 설정

        layout_main = QHBoxLayout()
        layout_left = QVBoxLayout()
        layout_right = QVBoxLayout()

        layout_main.addLayout(layout_left)
        layout_main.addLayout(layout_right)

        List1 = ["name", "PID"]
        table1 = QTableWidget()
        table1.setColumnCount(2)


        for i in range(2):
            item1 = QTableWidgetItem(List1[i])
            item1.setBackground(QColor(255, 0, 0))
            item1.setFont(QFont('나눔고딕', 10, QFont.Bold))
            table1.setHorizontalHeaderItem(i, item1)

        #table1.setHorizontalHeaderLabels(List1)

        table1.setColumnWidth(0, 450)
        table1.setColumnWidth(1, 190)
        table1.setRowCount(len(pstree_data))



        i = 0
        for key, value in pstree_data.items():
            table1.setItem(i, 0, QTableWidgetItem(str(value['name'])))
            table1.setItem(i, 1, QTableWidgetItem(str(key)))
            for kk, vv in result_data.items():
                if len(vv) > 0 and key == vv['pid']:
                    for k in range(2):
                        table1.item(i, k).setBackground(QColor(255, 202, 213))
            i = i + 1

        for i in range(len(pstree_data)):
            table1.item(i, 0).setTextAlignment(Qt.AlignCenter)
            table1.item(i, 1).setTextAlignment(Qt.AlignCenter)

        table1.setMinimumHeight(260)
        table1.setMinimumWidth(670)
        table1.setMaximumHeight(260)
        table1.setMaximumWidth(670)
        self.box.setAlignment(Qt.AlignCenter)
        table1.verticalHeader().setVisible(False)
        table1.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 셀 edit 금지
        table1.setAlternatingRowColors(True)
        """table1.horizontalHeader().setStyleSheet(
            "background-color: red;"
        )"""
        table1.cellClicked.connect(self.__mycell_clicked)

        treelabel = QLabel('Pstree')
        treelabel.setFont(QFont('나눔고딕', 10, QFont.Bold))
        treelabel.setStyleSheet(
            "border-style: solid;"
            "border-width: 2px;"
            "border-color: #c4c4c4;"
            "border-radius: 3px")
        treelabel.setAlignment(Qt.AlignCenter)
        treelabel.setMinimumWidth(680)
        treelabel.setMinimumHeight(35)
        treelabel.setMaximumHeight(35)
        layout_left.addWidget(treelabel, alignment=Qt.AlignLeft | Qt.AlignTop)
        layout_left.addWidget(table1, alignment=Qt.AlignLeft)

        List2 = ["Offset", "Name", "PID", "Pslist", "Psscan", "thrdproc", "pspcid", "csrss", "sesssion", "deskthrd"]

        table2 = QTableWidget()
        table2.setColumnCount(10)

        i=0
        for i in range(10):
            item1 = QTableWidgetItem(List2[i])
            item1.setBackground(QColor(255, 0, 0))
            item1.setFont(QFont('나눔고딕', 8, QFont.Bold))
            table2.setHorizontalHeaderItem(i, item1)

        table2.setColumnWidth(0, 250)
        table2.setColumnWidth(1, 250)
        table2.setColumnWidth(2, 250)
        table2.setColumnWidth(3, 250)
        table2.setColumnWidth(4, 250)
        table2.setRowHeight(0,70)
        table2.setRowCount(1)

        table2.setMinimumHeight(110)
        table2.setMinimumWidth(670)
        table2.setMaximumHeight(110)
        table2.setMaximumWidth(670)
        table2.resizeColumnsToContents()
        table2.verticalHeader().setVisible(False)
        table2.setEditTriggers(QAbstractItemView.NoEditTriggers)

        detail = QLabel('Detail Information')
        detail.setFont(QFont('나눔고딕', 10, QFont.Bold))
        detail.setStyleSheet(
            "border-style: solid;"
            "border-width: 2px;"
            "border-color: #c4c4c4;"
            "border-radius: 3px")
        detail.setAlignment(Qt.AlignCenter)
        detail.setMinimumWidth(680)
        detail.setMinimumHeight(35)
        layout_right.addWidget(detail, alignment=Qt.AlignHCenter | Qt.AlignTop)

        psxview = QLabel('psxview')
        psxview.setFont(QFont('나눔고딕', 10, QFont.Bold))
        layout_right.addWidget(psxview, alignment=Qt.AlignHCenter | Qt.AlignTop)
        layout_right.addWidget(table2, alignment=Qt.AlignRight)

        List3 = ["Proto", "Local Address", "Foreign Address", "state", "PID", "Owner", "Count"]

        table3 = QTableWidget()
        table3.setColumnCount(7)

        i = 0
        for i in range(7):
            item1 = QTableWidgetItem(List3[i])
            item1.setBackground(QColor(255, 0, 0))
            item1.setFont(QFont('나눔고딕', 8, QFont.Bold))
            table3.setHorizontalHeaderItem(i, item1)

        table3.setColumnWidth(0, 150)
        table3.setColumnWidth(1, 250)
        table3.setColumnWidth(2, 250)
        table3.setColumnWidth(3, 150)
        table3.setColumnWidth(4, 120)
        table3.setColumnWidth(5, 240)
        table3.setColumnWidth(6, 80)
        table3.setRowCount(1)

        table3.setMinimumHeight(110)
        table3.setMinimumWidth(670)
        table3.setMaximumHeight(110)
        table3.setMaximumWidth(670)
        table3.resizeColumnsToContents()
        table3.verticalHeader().setVisible(False)
        table3.setEditTriggers(QAbstractItemView.NoEditTriggers)

        netscan = QLabel('netscan')
        netscan.setFont(QFont('나눔고딕', 10, QFont.Bold))
        layout_right.addStretch(2)
        layout_right.addStretch(1)
        layout_right.addWidget(netscan, alignment=Qt.AlignHCenter | Qt.AlignTop)
        layout_right.addWidget(table3, alignment=Qt.AlignRight | Qt.AlignBottom)

        self.box.addLayout(layout_main)

        self.table1 = table1
        self.table2 = table2
        self.table3 = table3

    def __mycell_clicked(self, item):
        currentitem = self.table1.item(item, 1).text()
        currentitem2 = self.table1.item(item, 0).text()
        print(type(currentitem))
        print(int(currentitem))
        self.getpsxview(int(currentitem))
        self.getnetscan(int(currentitem), currentitem2)

    def getpsxview(self, pid):
        for key, value in psxview_data.items():
            if int(value['pid']) == int(pid):
                print('1success')
                self.table2.setItem(0, 0, QTableWidgetItem(str(value['offset'])))
                self.table2.setItem(0, 1, QTableWidgetItem(str(key)))
                self.table2.setItem(0, 2, QTableWidgetItem(str(value['pid'])))
                self.table2.setItem(0, 3, QTableWidgetItem(str(value['pslist'])))
                self.table2.setItem(0, 4, QTableWidgetItem(str(value['psscan'])))
                self.table2.setItem(0, 5, QTableWidgetItem(str(value['thrdproc'])))
                self.table2.setItem(0, 6, QTableWidgetItem(str(value['pspcid'])))
                self.table2.setItem(0, 7, QTableWidgetItem(str(value['csrss'])))
                self.table2.setItem(0, 8, QTableWidgetItem(str(value['session'])))
                self.table2.setItem(0, 9, QTableWidgetItem(str(value['deskthrd'])))
                self.table2.resizeColumnsToContents()
                break
            else:
                self.table2.setItem(0, 0, QTableWidgetItem('none'))
                self.table2.setItem(0, 1, QTableWidgetItem('none'))
                self.table2.setItem(0, 2, QTableWidgetItem('none'))
                self.table2.setItem(0, 3, QTableWidgetItem('none'))
                self.table2.setItem(0, 4, QTableWidgetItem('none'))
                self.table2.setItem(0, 5, QTableWidgetItem('none'))
                self.table2.setItem(0, 6, QTableWidgetItem('none'))
                self.table2.setItem(0, 7, QTableWidgetItem('none'))
                self.table2.setItem(0, 8, QTableWidgetItem('none'))
                self.table2.setItem(0, 9, QTableWidgetItem('none'))

    def getnetscan(self, pid, name):
        for key, value in netscan_data.items():
            if key.isdigit() and int(key) == int(pid): #키가 숫자가 아닌게 존재함,
                print('2success')
                self.table3.setItem(0, 0, QTableWidgetItem(str(value['protocol'])))
                self.table3.setItem(0, 1, QTableWidgetItem(str(value['local address'])))
                self.table3.setItem(0, 2, QTableWidgetItem(str(value['foreign address'])))
                self.table3.setItem(0, 3, QTableWidgetItem(str(value['state'])))
                self.table3.setItem(0, 4, QTableWidgetItem(str(key)))
                self.table3.setItem(0, 5, QTableWidgetItem(str(value['name'])))
                self.table3.setItem(0, 6, QTableWidgetItem(str(value['count'])))
                self.table3.resizeColumnsToContents()
                break
            elif value['name'] == name:
                print('2success')
                self.table3.setItem(0, 0, QTableWidgetItem(str(value['protocol'])))
                self.table3.setItem(0, 1, QTableWidgetItem(str(value['local address'])))
                self.table3.setItem(0, 2, QTableWidgetItem(str(value['foreign address'])))
                self.table3.setItem(0, 3, QTableWidgetItem(str(value['state'])))
                self.table3.setItem(0, 4, QTableWidgetItem(str(key)))
                self.table3.setItem(0, 5, QTableWidgetItem(str(value['name'])))
                self.table3.setItem(0, 6, QTableWidgetItem(str(value['count'])))
            else:
                self.table3.setItem(0, 0, QTableWidgetItem('none'))
                self.table3.setItem(0, 1, QTableWidgetItem('none'))
                self.table3.setItem(0, 2, QTableWidgetItem('none'))
                self.table3.setItem(0, 3, QTableWidgetItem('none'))
                self.table3.setItem(0, 4, QTableWidgetItem('none'))
                self.table3.setItem(0, 5, QTableWidgetItem('none'))
                self.table3.setItem(0, 6, QTableWidgetItem('none'))

class Hivelist(StWidgetForm):
    """
    Hive List 탭
    """

    def __init__(self):
        super(Hivelist, self).__init__()
        self.setStyleSheet("border: 0px")
        self.initUI()

    def initUI(self):
        List = ["name", "virtual"]
        table = QTableWidget()
        table.setColumnCount(2)

        i = 0
        for i in range(2):
            item1 = QTableWidgetItem(List[i])
            item1.setBackground(QColor(255, 0, 0))
            item1.setFont(QFont('나눔고딕', 10, QFont.Bold))
            table.setHorizontalHeaderItem(i, item1)

        table.setColumnWidth(0, 800)
        table.setColumnWidth(1, 450)
        table.setRowCount(len(hivelist_data))

        i = 0
        for key, value in hivelist_data.items():
            table.setItem(i, 0, QTableWidgetItem(str(value['name'])))
            table.setItem(i, 1, QTableWidgetItem(str(value['virtual'])))
            if value['name'] in result_reg_data:
                for k in range(2):
                    table.item(i, k).setBackground(QColor(255, 202, 213))
            i = i + 1


        label = QLabel('Hivelist')
        label.setFont(QFont('나눔고딕', 10, QFont.Bold))
        label.setStyleSheet(
            "border-style: solid;"
            "border-width: 2px;"
            "border-color: #c4c4c4;"
            "border-radius: 3px")
        label.setAlignment(Qt.AlignCenter)
        label.setMinimumWidth(670)
        label.setMinimumHeight(35)
        label.setMaximumHeight(35)
        self.box.addWidget(label, alignment=Qt.AlignHCenter | Qt.AlignTop)
        table.setMinimumHeight(270)
        table.setMinimumWidth(670)
        table.setMaximumHeight(270)
        table.setMaximumWidth(670)
        table.resizeColumnsToContents()
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.box.addWidget(table, alignment=Qt.AlignVCenter)


class Layout_Registry(StWidgetForm):
    """
    Print Key 탭
    """

    def __init__(self):
        super(Layout_Registry, self).__init__()
        self.setStyleSheet("border: 0px")
        self.initUI()

    def initUI(self):

        layout_main = QHBoxLayout()
        layout_left = QVBoxLayout()
        layout_right = QVBoxLayout()

        layout_main.addLayout(layout_left)
        layout_main.addLayout(layout_right)

        List1 = ["name", "virtual"]
        table1 = QTableWidget()
        table1.setColumnCount(2)

        i = 0
        for i in range(2):
            item1 = QTableWidgetItem(List1[i])
            item1.setBackground(QColor(255, 0, 0))
            item1.setFont(QFont('나눔고딕', 10, QFont.Bold))
            table1.setHorizontalHeaderItem(i, item1)

        table1.setColumnWidth(0, 800)
        table1.setColumnWidth(1, 450)
        table1.setRowCount(len(hivelist_data))

        i = 0
        for key, value in hivelist_data.items():
            table1.setItem(i, 0, QTableWidgetItem(str(value['name'])))
            table1.setItem(i, 1, QTableWidgetItem(str(value['virtual'])))
            if value['name'] in result_reg_data:
                for k in range(2):
                    table1.item(i, k).setBackground(QColor(255, 202, 213))
            i = i + 1

        label1 = QLabel('Hivelist')
        label1.setFont(QFont('나눔고딕', 10, QFont.Bold))
        label1.setStyleSheet(
            "border-style: solid;"
            "border-width: 2px;"
            "border-color: #c4c4c4;"
            "border-radius: 3px")
        label1.setAlignment(Qt.AlignCenter)
        label1.setMinimumWidth(670)
        label1.setMinimumHeight(35)
        label1.setMaximumHeight(35)
        layout_left.addWidget(label1, alignment=Qt.AlignHCenter | Qt.AlignTop)
        table1.setMinimumHeight(270)
        table1.setMinimumWidth(670)
        table1.setMaximumHeight(270)
        table1.setMaximumWidth(670)
        table1.resizeColumnsToContents()
        table1.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table1.cellClicked.connect(self.__mycell_clicked)
        layout_left.addWidget(table1, alignment=Qt.AlignVCenter)


        List2 = ["Registry", "Option", "Last updated", "Values"]
        table2 = QTableWidget()
        table2.setColumnCount(4)

        i=0
        for i in range(4):
            item1 = QTableWidgetItem(List2[i])
            item1.setBackground(QColor(255, 0, 0))
            item1.setFont(QFont('나눔고딕', 10, QFont.Bold))
            table2.setHorizontalHeaderItem(i, item1)

        table2.setColumnWidth(0, 680)
        table2.setColumnWidth(1, 100)
        table2.setColumnWidth(2, 120)
        table2.setColumnWidth(3, 600)
        table2.setRowCount(1)

        """i = 0
        for key, value in printkey_data.items():
            table2.setItem(i, 0, QTableWidgetItem(str(value['Registry'])))
            table2.setItem(i, 1, QTableWidgetItem('RUN(S)'))
            table2.setItem(i, 2, QTableWidgetItem(str(value['LastUpDate'])))
            table2.setItem(i, 3, QTableWidgetItem(str(value['value'])))
            if value['Registry'] in result_data:
                for k in range(4):
                    table2.item(i, k).setBackground(QColor(255, 202, 213))
            i = i + 1"""


        table2.setMinimumHeight(270)
        table2.setMinimumWidth(670)
        table2.setMaximumHeight(270)
        table2.setMaximumWidth(670)
        table2.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table2.resizeColumnsToContents()

        label = QLabel('Printkey')
        label.setFont(QFont('나눔고딕', 10, QFont.Bold))
        label.setStyleSheet(
            "border-style: solid;"
            "border-width: 2px;"
            "border-color: #c4c4c4;"
            "border-radius: 3px")
        label.setAlignment(Qt.AlignCenter)
        label.setMinimumWidth(670)
        label.setMinimumHeight(35)
        layout_right.addWidget(label, alignment=Qt.AlignLeft | Qt.AlignTop)
        layout_right.addWidget(table2, alignment=Qt.AlignLeft)

        self.box.addLayout(layout_main)
        self.table1 = table1
        self.table2 = table2

    def __mycell_clicked(self, item):
        currentitem = self.table1.item(item, 0).text()
        print(type(currentitem))
        self.getpintkey(currentitem)

    def getpintkey(self, name):
        print(name)
        print(type(name))
        for key, value in printkey_data.items():
            if value['Registry'] == name:
                print('1success')
                self.table2.setItem(0, 0, QTableWidgetItem(str(value['Registry'])))
                self.table2.setItem(0, 1, QTableWidgetItem('RUN(S)'))
                self.table2.setItem(0, 2, QTableWidgetItem(str(value['LastUpDate'])))
                self.table2.setItem(0, 3, QTableWidgetItem(str(value['value'])))
                self.table2.resizeColumnsToContents()
                break
            else:
                self.table2.setItem(0, 0, QTableWidgetItem('none'))
                self.table2.setItem(0, 1, QTableWidgetItem('none'))
                self.table2.setItem(0, 2, QTableWidgetItem('none'))
                self.table2.setItem(0, 3, QTableWidgetItem('none'))
                self.table2.resizeColumnsToContents()
"""
class Layout_Registry(StWidgetForm):

    def __init__(self):
        super(Layout_Registry, self).__init__()
        self.setStyleSheet("border: 0px")
        self.initUI()

    def initUI(self):
        # QTreeView 생성 및 설정

        layout_main = QHBoxLayout()
        layout_left = QHBoxLayout()
        layout_right = QHBoxLayout()

        layout_main.addLayout(layout_left)
        layout_main.addLayout(layout_right)

        layout_left.addStretch(1)
        layout_left.addWidget(Hivelist(), alignment=Qt.AlignLeft | Qt.AlignTop)
        layout_right.addWidget(PrintKey(), alignment=Qt.AlignRight | Qt.AlignTop)
        layout_right.addStretch(1)
        self.box.addLayout(layout_main)"""

class Memory_main(StWidgetForm):
    """
    메모리 분석 화면
    """

    def __init__(self, dirname):
        super(Memory_main, self).__init__()
        Memory_JSON(dirname)
        self.setStyleSheet("background-color: white")
        self.setGeometry(150, 120, 1400, 900)
        self.initUI()

    def initUI(self):
        # 상단바, 기존 화면 레이아웃 생성 및 추가
        layout_main = QVBoxLayout()
        layout_image = QVBoxLayout()
        layout_top = QHBoxLayout()
        layout_bottom = QHBoxLayout()

        self.box.addLayout(layout_main)

        process = QLabel('PROCESS')
        process.setFont(QFont('Chakra Petch SemiBold', 15, QFont.Bold))
        process.setAlignment(Qt.AlignCenter)
        process.setStyleSheet(
            "color : #FFFFFF;"
            "border-width: 1px;"
            "border-color: #000000;"
            "border-radius: 5px;"
            "background-color: #AAAAAA;"
        )
        process.setMinimumWidth(1400)
        process.setMinimumHeight(40)
        list = [0, 0]
        i = 0
        for key, value in imageinfo_data.items():
            list[i] = str(value)
            i = i + 1
        label1 = QLabel('  Image Data And Time: ' + list[1])
        label1.setFont(QFont('나눔고딕', 11, QFont.Bold))
        layout_image.addWidget(label1, alignment=Qt.AlignTop)

        registry = QLabel('REGISTRY')
        registry.setFont(QFont('Chakra Petch SemiBold', 15, QFont.Bold))
        registry.setAlignment(Qt.AlignCenter)
        registry.setStyleSheet(
            "color : #FFFFFF;"
            "border-width: 1px;"
            "border-color: #000000;"
            "border-radius: 5px;"
            "background-color: #AAAAAA;")
        registry.setMinimumWidth(1400)
        registry.setMinimumHeight(40)


        layout_main.addLayout(layout_image)
        layout_main.addWidget(process, alignment=Qt.AlignCenter)
        layout_main.addLayout(layout_top)
        layout_main.addStretch(1)
        layout_main.addWidget(registry, alignment=Qt.AlignCenter)
        layout_main.addLayout(layout_bottom)

        # 중간, 아래 부분의 위젯 생성 및 부착
        top_widget = Layout_Process()
        top_widget.setMinimumHeight(370)
        top_widget.setMaximumHeight(370)
        top_widget.setMinimumWidth(1400)
        top_widget.setMaximumWidth(1400)
        bottom_widget = Layout_Registry()
        bottom_widget.setMinimumHeight(370)
        bottom_widget.setMaximumHeight(370)
        bottom_widget.setMinimumWidth(1400)
        bottom_widget.setMaximumWidth(1400)

        layout_top.addWidget(top_widget, alignment=Qt.AlignCenter)
        layout_bottom.addWidget(bottom_widget, alignment=Qt.AlignCenter)

        """self.setWindowTitle('Find Wally')
        self.show()"""

"""class MyApp(QMainWindow, QWidget):
    # 크기 및 출력 위치를 변경
    def __init__(self):
        super().__init__()
        self.stk_w = QStackedWidget(self)
        self.setGeometry(150, 120, 1400, 900)
        self.initUI()

    def initUI(self):
        # 레이아웃 시작

        # 레이아웃 생성
        wid = QWidget(self)
        self.setCentralWidget(wid)
        layout1 = QVBoxLayout()

        layout1.addWidget(Memory_main())
        wid.setLayout(layout1)
        self.setWindowTitle('Find Wally')
        self.show()"""

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Memory_main("20201121-150119")
    sys.exit(app.exec_())