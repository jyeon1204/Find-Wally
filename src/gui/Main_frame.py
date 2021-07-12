import glob
import multiprocessing
import os
import sys
import threading
from threading import Thread
from multiprocessing import Process, Queue
import os, sys, time

from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QEvent
from PyQt5.QtWidgets import *

from src.core.Sysmon.Sysmon_Event_Collecter import get_event_final, sysmon_main
from src.core.memory.memory_main import memory_main
from src.gui.DefenderLog_frame import Amsi_main
from src.gui.EventLogAnalysis_frame import fileopen, getdir, Sys_main
from src.gui.MemoryAnalysis_frame import Memory_main, Memory_JSON

class MyApp(QMainWindow, QWidget):

    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)  # conditions are associated with locks
        self.setGeometry(150, 120, 1400, 900)
        self.initUI()
        self.tab_session = 0
        # sysmon_main()

    def initUI(self):
        exitAction = QAction(QIcon('exit.png'), 'Exit', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.setStatusTip('Exit application')
        exitAction.triggered.connect(self.exitAction)

        # 메모리 분석 메뉴바
        newMemory = QAction(QIcon('exit.png'), 'New Memory Analysis', self)
        newMemory.setShortcut('Ctrl+M')
        newMemory.triggered.connect(self.btn_newMemroy_menu)
        self.newMemory = newMemory

        # 이벤트 로그 메뉴바
        newEventLog = QAction(QIcon('exit.png'), 'New Event Log Analysis', self)
        newEventLog.setShortcut('Ctrl+E')
        newEventLog.triggered.connect(self.btn_newEventLog_menu)
        # loadEventLogResult = QAction(QIcon('exit.png'), 'Load Event Log Analysis Result', self)
        # loadEventLogResult.triggered.connect(self.btn_loadEventLogResult_menu)

        # 실시간 탐지 관련 이벤트 로그바
        loadDefenderEventLog = QAction(QIcon('exit.png'), 'Load Defender Envent Log', self)
        loadDefenderEventLog.triggered.connect(self.btn_loadDefenderEventLog_menu)

        menubar = self.menuBar()
        menubar.setNativeMenuBar(False)
        filemenu = menubar.addMenu('&File')
        self.filemenu = filemenu
        # 'File' 메뉴 바에 메뉴 넣기
        filemenu.addAction(newMemory)
        ## load memory result 하위 메뉴 넣기
        loadMemoryResult = filemenu.addMenu('&Load Memory Analysis Result')
        self.LoadMemoryResult = loadMemoryResult
        filemenu.addMenu(loadMemoryResult)
        ## 폴더명 긁어오기
        dir_list = getVolatilityDir()
        for name in dir_list:
            last_file = QAction(name, self)
            last_file.setProperty("name", name)
            loadMemoryResult.addAction(last_file)
            # loadMemoryResult.triggered.connect(self.btn_loadMemoryResult())
            last_file.triggered.connect(lambda temp=name, name=str(name):self.btn_loadMemoryResult(name))
            # clickable(last_file).con

        f5Action = QAction(QIcon('exit.png'), 'Refresh', self)
        f5Action.setStatusTip('refresh')
        f5Action.triggered.connect(lambda:self.f5event())


        # Event Log 관련 메뉴
        filemenu.addAction(newEventLog)
        ## Load Event Log Result 하위 메뉴
        loadEventLogResult = filemenu.addMenu('&Load Event Log Result')
        filemenu.addMenu(loadEventLogResult)
        ## 폴더명 긁어오기
        dir_list_sys = getSysmonDir()
        filemenu.addMenu(loadEventLogResult)
        for name in dir_list_sys:
            last_file_sys = QAction(name, self)
            last_file_sys.setProperty("name", name)
            loadEventLogResult.addAction(last_file_sys)
            last_file_sys.triggered.connect(lambda temp=name, name=str(name): self.btn_loadEventLogResult_menu(name))
            # clickable(last_file).con

        # filemenu.addAction(newEventLog)
        # filemenu.addAction(loadEventLogResult)
        filemenu.addAction(loadDefenderEventLog)
        filemenu.addAction(f5Action)
        filemenu.addAction(exitAction)

        mainLayout = QWidget()
        mainLayout.setStyleSheet("background-color: #AAAAAA;")

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.tabs.setElideMode(Qt.ElideRight)
        self.tabs.setUsesScrollButtons(True)
        # self.tabCloseRequested.connect(self.closeTab)
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.closeTab)

        vbox = QVBoxLayout()
        vbox.addWidget(self.tabs)
        mainLayout.setLayout(vbox)
        self.setCentralWidget(mainLayout)
        self.setWindowTitle('WIW')
        self.show()

    def work(self):
        self.statusBar().showMessage('Ready')

    # 메모리 분석 메뉴 클릭 이벤트 - 탭 추가
    def btn_newMemroy_menu(self):
        self.tab_session += 1
        # print("THIS IS NEW Memory")
        newMomoryWindowReply = QMessageBox.question(
            self, 'WIW', "Do you want to start a new memory analysis?",
            QMessageBox.Yes |  QMessageBox.No, QMessageBox.No
        )
        if newMomoryWindowReply == QMessageBox.Yes:
            print('Yes clicked.')
            self.statusBar().showMessage('Loading ,,,, ')
            procname1 = multiprocessing.Process(target=memory_main, name="memory process")
            self.statusBar().showMessage('Doing Memory Analysis ,,,, ')
            procname1.start()
            print("name 직전")

            # name = getLateFile()
            # name = "20201122-021130"
            # tab_name = name + " #" + str(self.tab_session)
            # self.tabs.addTab(Memory_main(name), tab_name)

        elif newMomoryWindowReply == QMessageBox.No:
            print('No clicked.')

    ## 메모리 분석 결과 가져오기 클릭 이벤트
    def btn_loadMemoryResult(self, name):
        self.tab_session += 1
        print("TAB: ",name)
        tab_name = name + " #"+ str(self.tab_session)
        # dirname = name
        # print("dirname name :",name)
        self.tabs.addTab(Memory_main(name), tab_name)

    # 실시간 이벤트 로그 메뉴 클릭 이벤트 - 탭 추가
    def btn_loadDefenderEventLog_menu(self):
        name = "session"
        tab_name = name + " #" + str(self.tab_session)
        self.tab_session += 1
        self.tabs.addTab(Amsi_main(), tab_name)

    # 이벤트로그 분석 메뉴 클릭 이벤트 - 탭 추가
    def btn_newEventLog_menu(self):
        # self.tab_session += 1
        # name = "New Event Log"
        # tab_name = name + " #" + str(self.tab_session)
        procname2 = multiprocessing.Process(target=get_event_final, name="sysmon process")
        self.statusBar().showMessage('Doing Event Log Analysis ,,,, ')
        procname2.start()
        # get_event_final()
        print("=====")

        # get_event_final()
        # dir = getSysmonDir()
        # newdir = dir[:1]
        # print("=====")
        # print(newdir)
        # getdir(newdir)
        # P0_Image, P0_Pid, action, type, level, detected, Ruledata, data, Time, PName = fileopen(newdir)
        # self.tabs.addTab(Sys_main(), tab_name)

    def btn_loadEventLogResult_menu(self,name2):
        self.tab_session += 1
        # name = "Lod Event Log"
        name = getdir(name2)
        tab_name = name + " #" + str(self.tab_session)
        fileopen(name2)
        self.tabs.addTab(Sys_main(), tab_name)


    # 'File' 메뉴에서 exit 클릭 했을 때
    def exitAction(self):
        self.close()

    # 탭에서 'x' 버튼 눌렀을 때
    def closeTab(self, index):
        self.tab_session -= 1
        self.tabs.removeTab(index)

    def f5event(self):
        self.hide()
        os.system("python .\\Main_frame.py\"")

def getVolatilityDir():
    path = "..\\..\\program\\volatility"
    file_list = os.listdir(path)
    dir_list = list()
    for i in file_list:
        # 디렉토리만 선별하는 조건
        if os.path.isdir(path+r"\\"+i):
            dir_list.append(i)
    return dir_list
# def getLateFile():
#     path = "..\\..\\program\\volatility"
#     file_list = os.listdir(path)
#     dir_list = []
#     for i in file_list:
#         # 디렉토리만 선별하는 조건
#         if os.path.isdir(path+r"\\"+i):
#             dir_list.append(i)
#     print("---",dir_list)
#     cmd = list()
#     if len(dir_list)>1:
#         for word in dir_list:
#             one, two = word.split('-')
#             tmp = int(one) + int(two)
#             cmd.append(tmp)
#         index = cmd.index(max(cmd))
#         return dir_list[index]
#     else:
#         return dir_list[0]


def getSysmonDir():
    dir_sys = list()
    path = ".\\detected"
    file_list = os.listdir(path)
    for i in file_list:
        # 디렉토리만 선별하는 조건
        if os.path.isdir(path + r"\\" + i):
            dir_sys.append(i)
            #getdir(i)
    return dir_sys

def call_process():
    procname1 = multiprocessing.Process(target=memory_main, name="proc 1")
    procname1.start()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = MyApp()
    sys.exit(app.exec_())