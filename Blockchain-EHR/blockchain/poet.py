import binascii
import os
import json
import random
import time
import socket
from contextlib import closing

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS
import threading

from blockchain import Blockchain
from transaction import Transaction
from wallet import Wallet
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.PublicKey import RSA

app = Flask(__name__)
unauthenticated = Flask(__name__)

# enables opening up app to other nodes
CORS(app)
CORS(unauthenticated)

@app.route('/resetclock', methods = ['POST'])
def resetclock():
    def longTask():
        stat = 200
        while True:
            with open('data/peers.txt') as f:
                peerList = f.read().split('\n')
            timeList = []
            for i in peerList:
                timeList.append(random.randint(1,5))
            selectedPeerIndex = timeList.index(min(timeList))
            print(timeList)
            time.sleep(timeList[selectedPeerIndex]*60)
            api_url = "http://127.0.0.1:{}/mine".format(peerList[selectedPeerIndex])
            response = requests.post(api_url, json={})
            stat = response.status_code

    thread = threading.Thread(target=longTask)
    thread.start()
    return jsonify({"yay":"started"}),200

if __name__ == '__main__':
            from argparse import ArgumentParser

            parser = ArgumentParser()
            parser.add_argument('-p', '--port', type=int, default=4300)
            parser.add_argument('--host', type=str, default='localhost')
            args = parser.parse_args()
            global host
            port, host = args.port, args.host
            if port == 2:
                unauthenticated.run(host=host, port=port)
            else:
                print(port, type(port))
                app.run(host=host, port=port)
