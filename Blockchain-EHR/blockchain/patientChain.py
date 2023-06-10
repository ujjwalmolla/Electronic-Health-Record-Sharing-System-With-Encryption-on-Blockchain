import sys
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication
import requests
import json


class MainWindow(QDialog):
    def __init__(self, widget, port, patient, doctor):
        super(MainWindow, self).__init__()
        loadUi("patientDetails.ui", self)
        self.patient = str(patient).strip()
        self.doctor = str(doctor).strip()
        self.port = port
        self.widget = widget
        self.back.clicked.connect(self.goback)
        self.tableWidget.setColumnWidth(0, 100)
        self.tableWidget.setColumnWidth(1, 100)
        self.tableWidget.setColumnWidth(2, 200)
        self.tableWidget.setColumnWidth(3, 200)
        self.tableWidget.setColumnWidth(4, 200)
        self.tableWidget.setColumnWidth(5, 180)
        self.tableWidget.setColumnWidth(6, 150)
        self.loaddata()

    def goback(self):
        # self.widget.setFixedWidth(480)
        # self.widget.setFixedHeight(620)
        self.widget.setCurrentIndex(self.widget.currentIndex() - 1)
        self.widget.removeWidget(self.widget.widget(self.widget.currentIndex() + 1))
    def conv_dict(self,details):
        res = []
        details= details[1:-1]
        for sub in details.split("',"):
            sub=sub.replace("'","")
            if ':' in sub:
                res.append(map(str.strip, sub.split(':', 1)))
        res = dict(res)
        return res

    def loaddata(self):
        api_url = "http://127.0.0.1:{}/patientchain".format(self.port)
        pr = {'patient': self.patient, "doctor": str(self.doctor).strip()}
        response = requests.post(api_url, json=pr).text
        response_info = json.loads(response)
        dict_chain = [block for block in response_info]
        row = 0
        l=0
        for i in range(len(dict_chain)):
            l = l + len(dict_chain[i]["transactions"])

        self.tableWidget.setRowCount(l)
        for dt in dict_chain:
            for tx in dt['transactions']:
                print(tx["doctor"], tx["hospital"], tx["details"])
                #d = self.conv_dict(tx["details"])
                d = tx["details"]
                print(d)
                print(type(d))
                self.tableWidget.setItem(row, 0, QtWidgets.QTableWidgetItem(tx["doctor"]))
                self.tableWidget.setItem(row, 1, QtWidgets.QTableWidgetItem(tx["hospital"]))
                self.tableWidget.setItem(row, 2, QtWidgets.QTableWidgetItem(tx["tid"]))
                # if len(d) <4:
                #     self.tableWidget.setItem(row, 3, QtWidgets.QTableWidgetItem(tx["details"]))
                #     self.tableWidget.setItem(row, 4, QtWidgets.QTableWidgetItem(tx["details"]))
                #     self.tableWidget.setItem(row, 5, QtWidgets.QTableWidgetItem(tx["details"]))
                #     self.tableWidget.setItem(row, 6, QtWidgets.QTableWidgetItem(tx["timestamp"]))
                # else:
                self.tableWidget.setItem(row, 3, QtWidgets.QTableWidgetItem(d["medicine"]))
                self.tableWidget.setItem(row, 4, QtWidgets.QTableWidgetItem(d["test"]))
                self.tableWidget.setItem(row, 5, QtWidgets.QTableWidgetItem(d["comments"]))
                self.tableWidget.setItem(row, 6, QtWidgets.QTableWidgetItem(d["create_time"]))
                # self.tableWidget.setItem(row, 6, QtWidgets.QTableWidgetItem(tx["timestamp"]))
                row = row+1
