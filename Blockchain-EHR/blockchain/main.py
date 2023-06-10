import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.uic import loadUi
from datetime import datetime
from patientChain import MainWindow as P
from doctorChain import MainWindow as D
from hospitalChain import MainWindow as H
from addTransaction import MainWindow as T



class MainWindow(QDialog):
    def __init__(self, widget, port, doctor):
        super(MainWindow,self).__init__()
        loadUi("mainwindow.ui",self)
        self.port = port
        self.widget = widget
        self.doctor = doctor
        self.patientbutton.clicked.connect(self.patfunction)
        self.doctorbutton.clicked.connect(self.docfunction)
        # self.hospbutton.clicked.connect(self.hosfunction)
        self.recordbutton.clicked.connect(self.gotoaddrecord)
        self.back.clicked.connect(self.goback)

    def goback(self):
        # self.widget.setFixedWidth(480)
        # self.widget.setFixedHeight(620)
        self.widget.setCurrentIndex(self.widget.currentIndex() - 1)
        self.widget.removeWidget(self.widget.widget(self.widget.currentIndex()+1))



    def gotoaddrecord(self):
        addreco = Addrecord(self.widget, self.port, self.doctor)
        self.widget.addWidget(addreco)
        self.widget.setCurrentIndex(self.widget.currentIndex()+1)
    def patfunction(self):
        mainwin = P(self.widget, self.port, self.patient.text(), self.doctor)
        self.widget.setFixedWidth(1410)
        self.widget.setFixedHeight(798)
        self.widget.setGeometry(0, 0, 1410, 798)
        # self.widget.showFullScreen()
        # self.widget.showMaximized()
        self.widget.addWidget(mainwin)
        self.widget.setCurrentIndex(self.widget.currentIndex() + 1)

    def docfunction(self):
        mainwin = D(self.widget, self.port, self.doctor)
        self.widget.setFixedWidth(1410)
        self.widget.setFixedHeight(798)
        self.widget.setGeometry(0, 0, 1410, 798)
        # self.widget.showFullScreen()
        # self.widget.showMaximized()
        self.widget.addWidget(mainwin)
        self.widget.setCurrentIndex(self.widget.currentIndex() + 1)

    def hosfunction(self):
        mainwin = H(self.widget,self.port,self.hospital.text())
        self.widget.setFixedWidth(1410)
        self.widget.setFixedHeight(798)
        self.widget.setGeometry(0, 0, 1410, 798)
        # self.widget.showFullScreen()
        # self.widget.showMaximized()
        self.widget.addWidget(mainwin)
        self.widget.setCurrentIndex(self.widget.currentIndex() + 1)
class Addrecord(QDialog):
    def __init__(self,widget,port,doctor):
        super(Addrecord, self).__init__()
        loadUi("addTransaction.ui", self)
        self.widget = widget
        self.port = port
        self.doctor = doctor
        self.addrecobutton.clicked.connect(self.addrecofunction)
        self.back.clicked.connect(self.goback)
        # self.tableWidget.setColumnWidth(0, 250)
        # self.tableWidget.setColumnWidth(1, 100)
        # self.tableWidget.setColumnWidth(2, 450)

    def goback(self):
        # self.widget.setFixedWidth(480)
        # self.widget.setFixedHeight(620)
        self.widget.setCurrentIndex(self.widget.currentIndex() - 1)
        self.widget.removeWidget(self.widget.widget(self.widget.currentIndex()+1))

    def addrecofunction(self):
        patient = self.patient.text()
        doctor = self.doctor
        hospital = self.port
        medicine = self.medicine.text()
        test = self.test.text()
        comments = self.comments.text()
        t = str(datetime.now())
        details = { "medicine": medicine,
                    "test": test,
                    "comments": comments,
                    "create_time": t}
        print("details type", type(details))
        mainwin = T(self.widget, self.port, patient, doctor, hospital, details)
        self.widget.setFixedWidth(1410)
        self.widget.setFixedHeight(798)
        self.widget.setGeometry(0, 0, 1410, 798)
        # self.widget.showFullScreen()
        # self.widget.showMaximized()
        self.widget.addWidget(mainwin)
        self.widget.setCurrentIndex(self.widget.currentIndex())


