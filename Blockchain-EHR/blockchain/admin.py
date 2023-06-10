import sys
import os
import socket
import subprocess
import threading
import time
import os.path
from pathlib import Path
import json
from block import Block
import requests
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QComboBox
from PyQt5.uic import loadUi
from PyQt5.QtWidgets import QMessageBox
from flask import Flask
from flask_cors import CORS

from main import MainWindow as mainWind
from mainPatient import MainWindow as pmain


class Admin(QDialog):
    def __init__(self):
        super(Admin, self).__init__()
        loadUi("admin.ui", self)
        self.proceses = []
        self.port = 4000
        self.init_admin()
        self.init_authserver()
        self.init_dataproc()
        self.networkBtn.clicked.connect(self.startnetwork)
        self.removebutton.clicked.connect(self.removenode)
        self.channelBtn.clicked.connect(self.joinchannel)
        self.addnodebtn.clicked.connect(self.addnode)
        self.mineButton.clicked.connect(self.mine_function)
        self.opntrnxnBttn.clicked.connect(self.get_opentransaction)
        # self.keyBtn.clicked.connect(self.create_keys)
        self.peerbutton.clicked.connect(self.get_nodes)

    def init_admin(self):
        try:
            self.pid = subprocess.Popen(
                "python3 node.py --port {}".format(self.port), shell=True).pid
            self.proceses.append(self.pid)
            print("pid", self.pid)
            time.sleep(5)
            my_file = "./data/wallet-{}.json".format(self.port)

            if os.path.isfile(my_file):
                api_url = "http://127.0.0.1:{}/load_keys".format(self.port)
                response = requests.get(api_url)
                if response.status_code == 200:
                    print("Keys loaded successfully!!")
                else:
                    print("Keys load failed!!")
                time.sleep(3)
            else:
                print("not found")
                api_url = "http://127.0.0.1:{}/create_keys".format(self.port)
                response = requests.post(api_url)
                if response.status_code == 200:
                    print("Keys created successfully!!")
                else:
                    print("Keys creatation failed!!")
                time.sleep(3)
            print("Admin started successfully")




        except FileNotFoundError:
            print("Node is already running or there is not node in the network :")
        print("Network started!!!!")
        msg = QMessageBox()
        msg.setWindowTitle("Network Running status")
        msg.setText("Admin Network started successfully!")
        x = msg.exec_()
        msg.setStandardButtons(QMessageBox.Ok)


    def init_authserver(self):
        try:
            self.pid = subprocess.Popen(
                "python3 authorisation.py --port {}".format(4100), shell=True).pid
            self.proceses.append(self.pid)
            print("pid", self.pid)
            time.sleep(5)
            my_file = "./data/wallet-{}.json".format(4100)

            if os.path.isfile(my_file):
                api_url = "http://127.0.0.1:{}/load_keys".format(4100)
                response = requests.get(api_url)
                if response.status_code == 200:
                    print("Keys of authorisation server loaded successfully!!")
                else:
                    print("Key loading of authorisation server failed!!")
                time.sleep(3)
            else:
                print("not found")
                api_url = "http://127.0.0.1:{}/create_keys".format(self.port)
                response = requests.post(api_url)
                if response.status_code == 200:
                    print("Keys of authorisation server created successfully!!")
                else:
                    print("Keys creatation of authorisation server  failed!!")
                time.sleep(3)
            print("Authorisation server started successfully")
        except FileNotFoundError:
            print("Node is already running or there is not node in the network :")
        msg = QMessageBox()
        msg.setWindowTitle("Authorisation Server Running status")
        msg.setText("Authorisation server started successfully!")
        x = msg.exec_()
        msg.setStandardButtons(QMessageBox.Ok)


    def init_dataproc(self):
        try:
            self.pid = subprocess.Popen(
                "python3 dataproc.py --port {}".format(4200), shell=True).pid
            self.proceses.append(self.pid)
            print("pid", self.pid)
            time.sleep(5)
            my_file = "./data/wallet-{}.json".format(4200)

            if os.path.isfile(my_file):
                api_url = "http://127.0.0.1:{}/load_keys".format(4200)
                response = requests.get(api_url)
                if response.status_code == 200:
                    print("Keys of data processing server loaded successfully!!")
                else:
                    print("Keys loading of data processing server  failed!!")
                time.sleep(3)
            else:
                print("not found")
                api_url = "http://127.0.0.1:{}/create_keys".format(4200)
                response = requests.post(api_url)
                if response.status_code == 200:
                    print("Keys of data processing server created successfully!!")
                else:
                    print("Keys creatation of data processing server failed!!")
                time.sleep(3)
            print("Data processing server started successfully")
        except FileNotFoundError:
            print("Node is already running or there is not node in the network :")
        msg = QMessageBox()
        msg.setWindowTitle("Data processing Server Running status")
        msg.setText("Data processing started successfully!")
        x = msg.exec_()
        msg.setStandardButtons(QMessageBox.Ok)

    def startnetwork(self):
        try:
            with open("data/peers.txt", "r") as peers:
                for p in peers:
                    if str(p).strip() == "4000":
                        continue
                    self.pid = subprocess.Popen(
                        "python3 node.py --port {}".format(p), shell=True).pid
                    self.proceses.append(self.pid)
                    time.sleep(5)

                    my_file = "./data/wallet-{}.json".format(str(p).strip())
                    print(my_file)
                    if os.path.isfile(my_file):
                        print("Keys found")
                        api_url = "http://127.0.0.1:{}/load_keys".format(p)
                        response = requests.get(api_url)
                        if response.status_code == 200:
                            print("Keys loaded successfully!!")
                        else:
                            print("Keys load failed!!")
                        time.sleep(5)
                    else:
                        print("Keys not found, needs to be created")
                        api_url = "http://127.0.0.1:{}/create_keys".format(p)
                        response = requests.post(api_url)
                        if response.status_code == 200:
                            print("Keys created successfully!!")
                        else:
                            print("Keys creatation failed!!")

                        time.sleep(5)
        except FileNotFoundError:
            print("Node is already running or there is not node in the network :")
        print("Network started!!!!")
        # api_url = "http://127.0.0.1:4300/resetclock"
        # response = requests.post(api_url)
        with open("data/peers.txt", "r") as peerfile:
            peers = peerfile.read().split('\n')
            def send_reset(peer):
                requests.post("http://127.0.0.1:{}/resetclock".format(peer))
            threads=[None] * len(peers)
            for i in range(len(peers)):
                print(peers[i])
                peer =  peers[i]
                threads[i] = threading.Thread(target = send_reset, args=(peer,))
                threads[i].start()
                print("resolve status: ", response)



        msg = QMessageBox()
        msg.setWindowTitle("Network Running status")
        msg.setText("Network started successfully!")
        x = msg.exec_()
        msg.setStandardButtons(QMessageBox.Ok)

    def joinchannel(self):
        peer_list=[]
        try:
            with open("data/peers.txt", "r") as peers:
                for p in peers:
                    peer_list.append(int(p))
        except FileNotFoundError:
            print("Peer list file not found :")
        for i in range(len(peer_list)):
            for j in range(len(peer_list)):
                if peer_list[i] != peer_list[j]:
                    api_url = "http://127.0.0.1:{}/add_node".format(peer_list[i])
                    pr = {'node': peer_list[j]}
                    response = requests.post(api_url, json=pr)
                    if response.status_code == 200:
                        print("Node {} is now connected with {}".format(peer_list[j],peer_list[i]))
                    else:
                        print(response.text)
                    time.sleep(3)
        msg = QMessageBox()
        msg.setWindowTitle("Channel status")
        msg.setText("All peers joined the channel!")
        x = msg.exec_()
        msg.setStandardButtons(QMessageBox.Ok)



    def get_nodes(self):
        # node = self.peer.text()
        node = self.port
        api_url = "http://127.0.0.1:{}/get_nodes".format(node)
        response = requests.get(api_url)
        print(response.json())
        print(response.json()["nodes"])
        res = list(response.json()["nodes"])
        res = (",\n").join([str(l) for l in res])

        msg = QMessageBox()
        msg.setWindowTitle("Peer list of Node {} ".format(node))
        msg.setText(res)
        x = msg.exec_()
        msg.setStandardButtons(QMessageBox.Ok)

    def addnode(self):
        node = self.newnodeid.text()
        msg = QMessageBox()
        msg.setWindowTitle("New Node Addition Status ")
        isnew = self.check_membership(node)
        if isnew:
            msg.setText("Could not add node {} to the network. The node already exists".format(node))
            x = msg.exec_()
            msg.setStandardButtons(QMessageBox.Ok)
            return False

        try:
            with open("data/peers.txt", "r") as peers:
                for p in peers:
                    api_url = "http://127.0.0.1:{}/add_node".format(p)
                    pr = {'node': int(node)}
                    response1 = requests.post(api_url, json=pr).text
                    print("response1", response1)
                    time.sleep(5)

            # start newly added node
            self.pid = subprocess.Popen(
                "python3 node.py --port {}".format(int(node)), shell=True).pid
            self.proceses.append(self.pid)
            time.sleep(5)

            # create keys for newly added key
            api_url = "http://127.0.0.1:{}/create_keys".format(int(node))
            response = requests.post(api_url).text
            print("keys creaded for new node", response)
            time.sleep(5)
            api_url = "http://127.0.0.1:{}/load_keys".format(int(node))
            response = requests.get(api_url)
            print("key loaded for new node, response", response)

            # add all the peer nodes to newly added node
            with open("data/peers.txt", "r") as peers:
                print("file opened")
                for p in peers:
                    print(p)
                    api_url = "http://127.0.0.1:{}/add_node".format(int(node))
                    pr = {'node': int(str(p).strip())}
                    response3 = requests.post(api_url, json=pr).text
                    print("response1", response3)
                    time.sleep(5)
            # add to the peer list
            peer = open("data/peers.txt", "a")
            peer.write(f"{int(node)}\n")
            peer.close()
            # update the chain
            api_url = "http://127.0.0.1:{}/resolve_conflicts".format(int(node))
            response = requests.post(api_url)
            print(response)

            print("Node addition process complete")
            msg.setText("New node {} added to the network successfully".format(node))
            x = msg.exec_()
            msg.setStandardButtons(QMessageBox.Ok)
            return True
        except FileNotFoundError:
            print("peers list file does not exists :")
            msg.setText("peers list file does not exists :")
            x = msg.exec_()
            msg.setStandardButtons(QMessageBox.Ok)
            return False


    def check_membership(self,node):
        try:
            with open("data/peers.txt", "r") as peers:
                for p in peers:
                    if str(p).strip() == str(node).strip():
                        return True
                print(" not present in peers file")
                return False
        except FileNotFoundError:
            print("peer list file does not exists :")
            return False

    def removenode(self):
        node = self.newnodeid.text()
        with open("peers.txt", "r") as f:
            lines = f.readlines()
        with open("peers.txt", "w") as f:
            for line in lines:
                if line.strip("\n") != str(node).strip():
                    f.write(line)
        with open("data/peers.txt", "r") as peers:
            for p in peers:
                api_url = "http://127.0.0.1:{}/remove_node/{}".format(p,node)
                print(api_url)
                # pr = {'node': str(node).strip()}
                response=requests.delete(api_url).text
                print(response)
                # response1 = requests.post(api_url, json=pr).text



    def mine_function(self):
        # miningnode = self.mine_node.text()
        miningnode = self.port
        api_url = "http://127.0.0.1:{}/mine".format(miningnode)
        response = requests.post(api_url)
        print(response)
        msg = QMessageBox()
        msg.setWindowTitle("Mining Status ")
        if response.status_code == 500:
            msg.setText("No transactions to add!")
        elif response.status_code == 409:
            msg.setText("Resolve conflicts first,block not added!")
        elif response.status_code == 200:
            msg.setText("Block added succesfully !")
        else:
            msg.setText("Adding block failed!")
        x = msg.exec_()
        msg.setStandardButtons(QMessageBox.Ok)
    #
    def get_opentransaction(self):
        # node = self.opentrnxn.text()
        node = self.port
        api_url = "http://127.0.0.1:{}/get_opentransactions".format(node)
        response = requests.get(api_url).text
        print(response , type(response))

        msg = QMessageBox()
        msg.setWindowTitle("Open transaction list ")
        msg.setText(response)
        x = msg.exec_()
        msg.setStandardButtons(QMessageBox.Ok)









app=QApplication(sys.argv)
mainwindow=Admin()
widget = QtWidgets.QStackedWidget()
widget.addWidget(mainwindow)
widget.setFixedWidth(530)
widget.setFixedHeight(620)
widget.show()
app.exec_()