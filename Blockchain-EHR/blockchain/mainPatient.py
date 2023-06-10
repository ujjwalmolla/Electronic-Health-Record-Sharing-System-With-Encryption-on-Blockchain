import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication
from PyQt5.uic import loadUi
from datetime import datetime
from patientSpecificChain import MainWindow as Pspec
from addPerm import MainWindow as Perm





class MainWindow(QDialog):
    def __init__(self, widget, port, patient):
        super(MainWindow,self).__init__()
        loadUi("patientmainwindow.ui",self)
        self.port = port
        self.widget = widget
        self.patient = patient
        self.patientbutton.clicked.connect(self.patfunction)
        self.permbutton.clicked.connect(self.permfunction)
        self.back.clicked.connect(self.goback)

    def goback(self):
        # self.widget.setFixedWidth(480)
        # self.widget.setFixedHeight(620)
        self.widget.setCurrentIndex(self.widget.currentIndex() - 1)
        self.widget.removeWidget(self.widget.widget(self.widget.currentIndex()+1))


    def patfunction(self):
        mainwin = Pspec(self.widget, self.port, self.patient)
        self.widget.setFixedWidth(1410)
        self.widget.setFixedHeight(798)
        self.widget.setGeometry(0, 0, 1410, 798)
        self.widget.addWidget(mainwin)
        self.widget.setCurrentIndex(self.widget.currentIndex() + 1)

    def permfunction(self):
        mainwin = Perm(self.widget, self.port, self.patient)
        self.widget.setFixedWidth(1410)
        self.widget.setFixedHeight(798)
        self.widget.setGeometry(0, 0, 1410, 798)
        self.widget.addWidget(mainwin)
        self.widget.setCurrentIndex(self.widget.currentIndex() + 1)



