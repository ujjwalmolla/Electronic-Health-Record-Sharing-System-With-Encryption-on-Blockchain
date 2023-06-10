import sys
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication
import requests
import json


class MainWindow(QDialog):
    def __init__(self, widget, port, hospital):
        super(MainWindow, self).__init__()
        loadUi("hospitalDetails.ui", self)
        self.hospital = hospital
        self.port = port
        self.widget = widget
        self.back.clicked.connect(self.goback)
        self.tableWidget.setColumnWidth(0, 250)
        self.tableWidget.setColumnWidth(1, 100)
        self.tableWidget.setColumnWidth(2, 250)
        self.tableWidget.setColumnWidth(3, 350)
        self.loaddata()

    def goback(self):
        # self.widget.setFixedWidth(480)
        # self.widget.setFixedHeight(620)
        self.widget.setCurrentIndex(self.widget.currentIndex() - 1)
        self.widget.removeWidget(self.widget.widget(self.widget.currentIndex() + 1))

    def loaddata(self):
        api_url = "http://127.0.0.1:{}/hospitalchain".format(self.port)
        pr = {'hospital': self.hospital}
        response = requests.post(api_url, json=pr).text
        response_info = json.loads(response)
        dict_chain = [block for block in response_info]
        row = 0
        l = 0
        for i in range(len(dict_chain)):
            l = l + len(dict_chain[i]["transactions"])

        self.tableWidget.setRowCount(l)
        for dt in dict_chain:
            for tx in dt['transactions']:
                print(tx["doctor"], tx["hospital"], tx["details"])
                self.tableWidget.setItem(row, 0, QtWidgets.QTableWidgetItem(tx["patient"]))
                self.tableWidget.setItem(row, 1, QtWidgets.QTableWidgetItem(tx["doctor"]))
                self.tableWidget.setItem(row, 2, QtWidgets.QTableWidgetItem(tx["hospital"]))
                self.tableWidget.setItem(row, 3, QtWidgets.QTableWidgetItem(tx["details"]))
                row = row+1



# # main
# app = QApplication(sys.argv)
# mainwindow = MainWindow()
# widget = QtWidgets.QStackedWidget()
# widget.addWidget(mainwindow)
# widget.setFixedHeight(850)
# widget.setFixedWidth(1120)
# widget.show()
# try:
#     sys.exit(app.exec_())
# except:
#     print("Exiting")