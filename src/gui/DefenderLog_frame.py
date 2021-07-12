import sys
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import subprocess

# import pandas as pd
from program.DefenderLog.EventLogParse import catalog_cd_df


class StWidgetForm(QGroupBox):
    """
    위젯 베이스 클래스
    """
    def __init__(self):
        QGroupBox.__init__(self)
        self.box = QBoxLayout(QBoxLayout.TopToBottom)
        self.setLayout(self.box)


class Level_square(StWidgetForm):
    def __init__(self, level):
        super(Level_square, self).__init__()
        self.level = int(level)
        #self.setStyleSheet("border: 0px")
        self.initUI()

    def initUI(self):
        # 상단바, 기존 화면 레이아웃 생성 및 추가
        layout_main = QHBoxLayout()
        self.box.addLayout(layout_main)

    def paintEvent(self, e):
        qp = QPainter()
        qp.begin(self)
        self.drawText(qp, str(self.level))

        if self.level == 5:
            self.draw_rect5(qp)
        elif self.level == 4:
            self.draw_rect4(qp)
        elif self.level == 3:
            self.draw_rect3(qp)
        elif self.level == 2:
            self.draw_rect2(qp)
        else:
            self.draw_rect1(qp)
        qp.end()

    def drawText(self, qp, level):
        qp.setPen(QColor(0, 0, 0))
        qp.setFont(QFont('스웨거 TTF', 28))
        qp.drawText(50, 63, 'LV. ' + level)

    def draw_rect1(self, qp):
        qp.setPen(QPen(Qt.white, 0))
        qp.setBrush(QColor(230, 230, 230))
        qp.drawRoundedRect(27, 80, 130, 40, 10, 10)
        qp.setBrush(QColor(230, 230, 230))
        qp.drawRoundedRect(27, 127, 130, 40, 10, 10)
        qp.setBrush(QColor(230, 230, 230))
        qp.drawRoundedRect(27, 174, 130, 40, 10, 10)
        qp.setBrush(QColor(230, 230, 230))
        qp.drawRoundedRect(27, 219, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 194, 194))
        qp.drawRoundedRect(27, 266, 130, 40, 10, 10)

    def draw_rect2(self, qp):
        qp.setPen(QPen(Qt.white, 0))
        qp.setBrush(QColor(230, 230, 230))
        qp.drawRoundedRect(27, 80, 130, 40, 10, 10)
        qp.setBrush(QColor(230, 230, 230))
        qp.drawRoundedRect(27, 127, 130, 40, 10, 10)
        qp.setBrush(QColor(230, 230, 230))
        qp.drawRoundedRect(27, 174, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 153, 153))
        qp.drawRoundedRect(27, 219, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 194, 194))
        qp.drawRoundedRect(27, 266, 130, 40, 10, 10)

    def draw_rect3(self, qp):
        qp.setPen(QPen(Qt.white, 0))
        qp.setBrush(QColor(230, 230, 230))
        qp.drawRoundedRect(27, 80, 130, 40, 10, 10)
        qp.setBrush(QColor(230, 230, 230))
        qp.drawRoundedRect(27, 127, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 97, 97))
        qp.drawRoundedRect(27, 174, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 153, 153))
        qp.drawRoundedRect(27, 219, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 194, 194))
        qp.drawRoundedRect(27, 266, 130, 40, 10, 10)

    def draw_rect4(self, qp):
        qp.setPen(QPen(Qt.white, 0))
        qp.setBrush(QColor(230, 230, 230))
        qp.drawRoundedRect(27, 80, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 59, 59))
        qp.drawRoundedRect(27, 127, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 97, 97))
        qp.drawRoundedRect(27, 174, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 153, 153))
        qp.drawRoundedRect(27, 219, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 194, 194))
        qp.drawRoundedRect(27, 266, 130, 40, 10, 10)

    def draw_rect5(self, qp):
        qp.setPen(QPen(Qt.white, 0))
        qp.setBrush(QColor(255, 0, 0))
        qp.drawRoundedRect(27, 80, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 59, 59))
        qp.drawRoundedRect(27, 127, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 97, 97))
        qp.drawRoundedRect(27, 174, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 153, 153))
        qp.drawRoundedRect(27, 219, 130, 40, 10, 10)
        qp.setBrush(QColor(255, 194, 194))
        qp.drawRoundedRect(27, 266, 130, 40, 10, 10)


class Amsi_LatestLog(StWidgetForm):
    """
    가장 최근 로그 정보 출력
    """
    def __init__(self):
        super(Amsi_LatestLog, self).__init__()
        self.setStyleSheet("border: 0px")
        self.initUI()

    def initUI(self):
        # 상단바, 기존 화면 레이아웃 생성 및 추가
        layout_main = QHBoxLayout()
        self.box.addLayout(layout_main)

        layout_left = QVBoxLayout()
        layout_right = QVBoxLayout()
        layout_main.addLayout(layout_left)
        layout_main.addLayout(layout_right)

        n = int(str(catalog_cd_df.loc[len(catalog_cd_df)-1]['Severity ID']))
        square = Level_square(n)
        square.setMinimumHeight(300)
        square.setMaximumWidth(200)
        layout_left.addWidget(square)

        # 라벨 생성
        # 설명 + Data의 노드 데이터 합쳐서 라벨로 출력

        #label1 = QLabel('제공자: ' + str(catalog_cd_df.loc[len(catalog_cd_df)-1]['Product Name']), self)
        label1 = QLabel('제공자: Windows Defender 바이러스 백신', self)
        layout_right.addWidget(label1)
        label2 = QLabel('탐지된 시간: ' + str(catalog_cd_df.loc[len(catalog_cd_df)-1]['Detection time']), self)
        layout_right.addWidget(label2)
        label3 = QLabel('위협의 이름: ' + str(catalog_cd_df.loc[len(catalog_cd_df)-1]['Treat Name']), self)
        layout_right.addWidget(label3)
        label4 = QLabel('위협 ID: ' + str(catalog_cd_df.loc[len(catalog_cd_df)-1]['Threat ID']), self)
        layout_right.addWidget(label4)
        label5 = QLabel('위험도: 심각', self)
        layout_right.addWidget(label5)
        label7 = QLabel('프로세스 이름: 바이러스', self)
        layout_right.addWidget(label7)
        label8 = QLabel('탐지한 사용자: ' + str(catalog_cd_df.loc[len(catalog_cd_df)-1]['Detection User']), self)
        layout_right.addWidget(label8)
        label9 = QLabel('경로: ' + str(catalog_cd_df.loc[len(catalog_cd_df)-1]['Path']), self)
        layout_right.addWidget(label9)
        label10 = QLabel('검색 유형: 구체적', self)
        layout_right.addWidget(label10)


class Amsi_LogList(StWidgetForm):
    """
    이전 탐지목록 출력
    """
    def __init__(self):
        super(Amsi_LogList, self).__init__()
        self.initUI()

    def initUI(self):
        # 상단바, 기존 화면 레이아웃 생성 및 추가
        List = ["위협 ID", "탐지한 주체", "탐지된 시간", "위험도", "경로"]
        scrollArea1 = QScrollArea()
        logtable = QTableWidget()
        logtable.setColumnCount(5)
        logtable.setHorizontalHeaderLabels(List)
        logtable.setColumnWidth(0, 123)
        logtable.setColumnWidth(1, 128)
        logtable.setColumnWidth(2, 250)
        logtable.setColumnWidth(3, 65)
        logtable.setColumnWidth(4, 690)
        logtable.setRowCount(len(catalog_cd_df.index))

        for i in range(len(catalog_cd_df.index)):
            logtable.setItem(i, 0, QTableWidgetItem(str(catalog_cd_df.loc[len(catalog_cd_df.index)-i-1]['Threat ID'])))
        for i in range(len(catalog_cd_df.index)):
            logtable.setItem(i, 1, QTableWidgetItem("Windows Defender 바이러스 백신"))
        for i in range(len(catalog_cd_df.index)):
            logtable.setItem(i, 2, QTableWidgetItem(str(catalog_cd_df.loc[len(catalog_cd_df.index)-i-1]['Detection time'])))
        for i in range(len(catalog_cd_df.index)):
            logtable.setItem(i, 3, QTableWidgetItem(str(catalog_cd_df.loc[len(catalog_cd_df.index)-i-1]['Severity ID'])))
        for i in range(len(catalog_cd_df.index)):
            logtable.setItem(i, 4, QTableWidgetItem(str(catalog_cd_df.loc[len(catalog_cd_df.index)-i-1]['Path'])))

        logtable.setMinimumHeight(470)
        logtable.setMinimumWidth(1316)
        logtable.resizeColumnsToContents()
        scrollArea1.setWidget(logtable)
        logtable.setAlternatingRowColors(True)
        layout_main = QVBoxLayout()
        layout_main.addWidget(scrollArea1)
        self.box.addLayout(layout_main)



class Amsi_main(StWidgetForm):
    """
    디펜더 로그 화면
    """
    def __init__(self):
        super(Amsi_main, self).__init__()
        self.setStyleSheet("background-color: white")
        self.setGeometry(150, 120, 1400, 900)
        self.setFixedWidth(1400)
        self.setFixedHeight(900)
        self.initUI()

    def initUI(self):
        # 상단바, 기존 화면 레이아웃 생성 및 추가
        layout_bar = QHBoxLayout()
        layout_main = QVBoxLayout()
        self.box.addLayout(layout_bar)
        self.box.addLayout(layout_main)

        # 최근 로그, 이전 로그 출력 창 부착
        latestlogwid = Amsi_LatestLog()
        latestlogwid.setMinimumHeight(350)
        layout_main.addWidget(latestlogwid)

        loglistwid = Amsi_LogList()
        loglistwid.setMinimumHeight(500)
        loglistwid.setMaximumHeight(550)
        layout_main.addWidget(loglistwid)

        #btn1.clicked.connect(self.click_btn1)
        #
        self.setWindowTitle('Find Wally')
        self.show()



class MyApp(QMainWindow, QWidget):
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

        layout1.addWidget(Amsi_main())
        wid.setLayout(layout1)
        self.setWindowTitle('Find Wally')
        self.show()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Amsi_main()
    sys.exit(app.exec_())