import json
import sys

import requests
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QMessageBox
from PyQt5.uic import loadUi
from datetime import datetime
from patientChain import MainWindow as P
from doctorChain import MainWindow as D
from hospitalChain import MainWindow as H
from addTransaction import MainWindow as T



class MainWindow(QDialog):
    def __init__(self, widget, port, patient):
        super(MainWindow,self).__init__()
        loadUi("addPerm.ui",self)
        self.port = port
        self.widget = widget
        self.patient = patient
        self.permbutton.clicked.connect(self.permfunction)
        self.back.clicked.connect(self.goback)

    def goback(self):
        # self.widget.setFixedWidth(480)
        # self.widget.setFixedHeight(620)
        self.widget.setCurrentIndex(self.widget.currentIndex() - 1)
        self.widget.removeWidget(self.widget.widget(self.widget.currentIndex()+1))

    def permfunction(self):
        doctor = str(self.doctor.text()).strip()
        hospital = str(self.hospital.text()).rstrip()
        details = { 'acc_type': 'patient',
                    'accessor': self.patient,
                    'nodeid': hospital,
                    'doctor': doctor}
        api_url = "http://127.0.0.1:{}/addperm".format(self.port)
        pr = {'patient': self.patient}
        response = requests.post(api_url, json=details)
        print(response)
        msg = QMessageBox()
        msg.setWindowTitle("Permission status")
        if response.status_code == 200:
            msg.setText("Permission successfully granted!!")
        else:
            msg.setText("Permission grant failed!!")

        x = msg.exec_()
        msg.setStandardButtons(QMessageBox.Ok)


