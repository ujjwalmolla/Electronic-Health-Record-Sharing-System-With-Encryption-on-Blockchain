import sys
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication
import requests
import json
import time
import uuid
from datetime import datetime
from PyQt5.QtWidgets import QMessageBox


class MainWindow(QDialog):
    def __init__(self, widget, port, patient, doctor, hospital, details):
        super(MainWindow, self).__init__()
        self.port = port
        self.patient = patient
        self.doctor = doctor
        self.hospital = hospital
        self.details = details
        self.widget = widget
        self.loaddata()

    def loaddata(self):
        api_url = "http://127.0.0.1:{}/add_transaction".format(self.port)
        txid = "TX"+str(uuid.uuid1())
        t = str(datetime.now().timestamp())
        print("txid",txid)
        print("received detils type",type(self.details))
        pr = {'patient': self.patient,
              'doctor': self.doctor,
              'hospital': self.port,
              'details': self.details,
              'tid': txid,
              'timestamp': t}
        response = requests.post(api_url, json=pr)
        msg = QMessageBox()
        msg.setWindowTitle("Record addition status")
        if response.status_code == 200:
            msg.setText("Record added successfully!")
        elif response.status_code == 400:
            msg.setText("Patient not registered!!!")
        else:
            msg.setText("Failed to add the record!")
        x = msg.exec_()
        msg.setStandardButtons(QMessageBox.Ok)

        return response
