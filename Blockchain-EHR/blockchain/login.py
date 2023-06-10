import sys

import requests
from PyQt5 import QtWidgets
from PyQt5.QtGui import QImage
from PyQt5.QtWidgets import QDialog, QApplication, QComboBox, QMessageBox
from PyQt5.uic import loadUi
from main import MainWindow as mainWind
from mainPatient import MainWindow as pmain


class Login(QDialog):
    def __init__(self):
        super(Login, self).__init__()
        loadUi("login.ui", self)
        # oImage = QImage("login_img.jpeg")
        self.loginbutton.clicked.connect(self.loginfunction)
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.createaccbutton.clicked.connect(self.gotocreate)

    def loginfunction(self):
        email = self.email.text()
        password = self.password.text()
        print(email)
        validated, port, email , usertype = self.validate(email, password)
        # print(usertype , len(usertype),type(usertype))
        if validated:
            if str(usertype).strip() =='Patient':
                mainwin = pmain(widget, port, email)
                widget.addWidget(mainwin)
                widget.setCurrentIndex(widget.currentIndex() + 1)
            else:
                mainwin = mainWind(widget, port, email)
                widget.addWidget(mainwin)
                widget.setCurrentIndex(widget.currentIndex() + 1)
        else:
            print("User Doesn't Exist!!!")
            msg = QMessageBox()
            msg.setWindowTitle("Login Status ")
            msg.setText("User Doesn't Exist!!!")
            x = msg.exec_()
            msg.setStandardButtons(QMessageBox.Ok)

    def validate(self, username, password):
        # Checks the text file for a username/password combination.
        try:
            with open("credentials.txt", "r") as credentials:
                for line in credentials:
                    line = line.split(",")
                    print(line[1],len(username),line[1]==username)
                    if line[1] == username and line[3] == password:
                        return True, line[5] , line[1], line[9]
                return False, None, None, None
        except FileNotFoundError:
            print("You need to Register first :")
            return False, None, None, None

    def gotocreate(self):
        createacc=CreateAcc(widget)
        widget.addWidget(createacc)
        widget.setCurrentIndex(widget.currentIndex()+1)
# pics = """MainWindow
# {
#     background-image : url(./login_img.jpeg);
# }
#
# """
class CreateAcc(QDialog):
    def __init__(self,widget):
        super(CreateAcc,self).__init__()
        loadUi("createacc.ui",self)
        self.widget = widget
        self.signupbutton.clicked.connect(self.createaccfunction)
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.confirmpass.setEchoMode(QtWidgets.QLineEdit.Password)
        self.patientradio.toggled.connect(self.passToggled1)
        self.hospitalradio.toggled.connect(self.passToggled2)
        self.back.clicked.connect(self.goback)

    def goback(self):
        # self.widget.setFixedWidth(480)
        # self.widget.setFixedHeight(620)
        self.widget.setCurrentIndex(self.widget.currentIndex() - 1)
        self.widget.removeWidget(self.widget.widget(self.widget.currentIndex()+1))

    def passToggled1(self):
        if not self.hospitalradio.isChecked():
            self.hospital.hide()
            self.hospitalbtn.hide()
    def passToggled2(self):
        if self.hospitalradio.isChecked():
            self.hospital.setVisible(True)
            self.hospitalbtn.setVisible(True)
    def createaccfunction(self):
        email = self.email.text()
        validation = self.validate_user(email)
        if not validation:
            print("Information", "That Username already exists")
        else:
            if self.password.text() == self.confirmpass.text():
                password = self.password.text()
                fname = self.name.text()
                if self.patientradio.isChecked():
                    utype = self.patientradio.text()
                if self.hospitalradio.isChecked():
                    utype = self.hospitalradio.text()
                if utype == "Patient":
                    port = 4000
                else:
                    port = self.hospital.text()
                credentials = open("credentials.txt", "a")
                credentials.write(f"Username,{email},Password,{password},Port,{port},Name,{fname},UserType,{utype}\n")
                credentials.close()

                api_url = "http://127.0.0.1:4100/createuserkey"
                pr = {'accessor': email}
                response = requests.post(api_url, json=pr)
                if response.status_code == 200:
                    # print("Successfully created acc with username: ", email, "and password: ", password)
                    msg = QMessageBox()
                    msg.setWindowTitle("User registration Status ")
                    msg.setText("User registered successfully")
                    x = msg.exec_()
                    msg.setStandardButtons(QMessageBox.Ok)
                else:
                    msg = QMessageBox()
                    msg.setWindowTitle("User registration Status ")
                    msg.setText("User could not be registered")
                    x = msg.exec_()
                    msg.setStandardButtons(QMessageBox.Ok)

                login = Login()
                widget.addWidget(login)
                widget.setCurrentIndex(widget.currentIndex()+1)


    def get_port(self):
        # Checks the text file for a username/password combination.
        try:
            f = open('availPorts.txt','r')
            data = f.read().split('\n')
            port = data[0]
            up = data[1:]
            f.close()
            f = open('availPorts.txt', 'w')
            f.write("\n".join(up))
            f.close()
            return port
        except FileNotFoundError:
            return False

    def validate_user(self,username):
        # Checks the text file for a username/password combination.
        try:
            with open("credentials.txt", "r") as credentials:
                for line in credentials:
                    line = line.split(",")
                    if line[1] == username:
                        return False
            return True
        except FileNotFoundError:
            return True




app=QApplication(sys.argv)
# app.setStyleSheet(pics)

mainwindow=Login()
widget = QtWidgets.QStackedWidget()
widget.addWidget(mainwindow)
# widget.setFixedWidth(480)
# widget.setFixedHeight(620)
widget.setFixedWidth(1400)
widget.setFixedHeight(750)
widget.setGeometry(0, 0, 1400, 750)



widget.show()
# widget.showMaximized()
app.exec_()