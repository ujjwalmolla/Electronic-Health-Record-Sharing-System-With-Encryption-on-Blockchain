import binascii
import os
import json
from time import time
import socket
from contextlib import closing

import Cryptodome
from flask import Flask, jsonify, request
from flask_cors import CORS
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.PublicKey import RSA


from blockchain import Blockchain
from transaction import Transaction
from wallet import Wallet

app = Flask(__name__)
unauthenticated = Flask(__name__)

# enables opening up app to other nodes
CORS(app)
CORS(unauthenticated)

@app.route('/createuserkey', methods=['POST'])
def crt_new_key():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400

    required_fields = ['accessor'] # , 'key']

    if not all(key in values for key in required_fields):
        response = {'message': 'Required data missing!'}

    accessor = values['accessor']
    # key = values['key']
    data = {}
    with open('data/server_bkp.json', mode='r') as f:
        data = json.load(f)
        alpha = Cryptodome.Random.get_random_bytes(16)
        data[accessor] = {
            'alpha': binascii.hexlify(alpha).decode('ascii')
        }
    with open('data/server_bkp.json', mode='w') as f:
        json.dump(data, f, indent=4)

    # encryptor = PKCS1_OAEP.new(RSA.importKey(binascii.unhexlify(key)))
    # alpha = binascii.hexlify(alpha).decode('ascii')
    # encrypted = encryptor.encrypt(str(alpha).encode('utf8 '))
    # response = {'alpha': binascii.hexlify(encrypted).decode('ascii')}
    response = {'alpha': "key created successfully"}
    return jsonify(response), 200

@app.route('/createtranskey', methods=['POST'])
def crt_trans_key():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400

    required_fields = ['accessor', 'transid', 'nodeid', 'doctor','key']

    if not all(key in values for key in required_fields):
        response = {'message': 'Required data missing!'}
        return jsonify(response), 400

    accessor = values['accessor']
    transid = values['transid']
    nodeid = values['nodeid']
    doctor = values['doctor']
    key = values['key']
    data = {}
    with open('data/server_bkp.json', mode='r') as f:
        data = json.load(f)
        try:
            data[accessor][transid] = {str(nodeid): [doctor]}
            alpha = data[accessor]["alpha"]   # binascii.unhexlify()
        except:
            response = {'error': "Patient does not exist, register the patient first!!"}
            return jsonify(response), 400

    with open('data/server_bkp.json', mode='w') as f:
        json.dump(data, f, indent=4)

    encryptor = PKCS1_OAEP.new(RSA.importKey(binascii.unhexlify(key)))
    seskey = binascii.hexlify(Cryptodome.Random.get_random_bytes(16)).decode('ascii')
    enc_ses = encryptor.encrypt(str(seskey).encode('utf8 '))

    encryptor_aes = AES.new(binascii.unhexlify(seskey), AES.MODE_EAX)
    encrypted = encryptor_aes.encrypt(str(alpha).encode('utf8 '))
    response = {'seskey':binascii.hexlify(enc_ses).decode('ascii'), 'alpha': binascii.hexlify(encrypted).decode('ascii'),
                'nonce':binascii.hexlify(encryptor_aes.nonce).decode('ascii')}
    return jsonify(response), 200

@app.route('/pushnonce', methods=['POST'])
def push_nonce():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400

    required_fields = ['accessor', 'transid', 'nonce']

    if not all(key in values for key in required_fields):
        response = {'message': 'Required data missing!'}
        return jsonify(response), 400

    accessor = values['accessor']
    transid = values['transid']
    enc = binascii.unhexlify(values['nonce'])

    decryptor = PKCS1_OAEP.new(RSA.importKey(
        binascii.unhexlify(wallet.private_key)))
    decrypted = decryptor.decrypt(enc)
    nonce = decrypted.decode('utf-8')#binascii.unhexlify(decrypted)
    data = {}
    with open('data/server_bkp.json', mode='r') as f:
        data = json.load(f)
        try:
            data[accessor][transid]["nonce"] = nonce
        except:
            response = {'error': "Patient does not exist, register the patient first!!"}
            print("here")
            return jsonify(response), 400

    with open('data/server_bkp.json', mode='w') as f:
        json.dump(data, f, indent=4)

    response = {'message':"Success!!!"}
    return jsonify(response), 200

@app.route('/gettranskey', methods=['POST'])
def get_trans_key():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400

    required_fields = ['accessor', 'transid', 'nodeid', 'doctor','key']

    if not all(key in values for key in required_fields):
        response = {'message': 'Required data missing!'}

    accessor = values['accessor']
    transid = values['transid']
    nodeid = values['nodeid']
    doctor = values['doctor']
    key = values['key']
    with open('data/server_bkp.json', mode='r') as f:
        rec = json.load(f)[accessor]
        if str(nodeid) in rec[str(transid)] and doctor in rec[str(transid)][str(nodeid)]:
            alpha = rec["alpha"] # binascii.unhexlify()
            nonce = rec[str(transid)]['nonce']
        else:
            response = {'error': 'invalid creds!!!'}
            return jsonify(response), 500
    encryptor = PKCS1_OAEP.new(RSA.importKey(binascii.unhexlify(key)))
    seskey = binascii.hexlify(Cryptodome.Random.get_random_bytes(16)).decode('ascii')
    enc_ses = encryptor.encrypt(str(seskey).encode('utf8 '))



    encryptor_aes = AES.new(binascii.unhexlify(seskey), AES.MODE_EAX)
    encrypted_a = encryptor_aes.encrypt(str(alpha).encode('utf8 '))
    #encrypted_a = encryptor.encrypt(str(alpha).encode('utf8 '))
    encrypted_n = encryptor_aes.encrypt(str(nonce).encode('utf8 '))
    response = {'seskey':binascii.hexlify(enc_ses).decode('ascii'),
        'alpha': binascii.hexlify(encrypted_a).decode('ascii'),
                'nonce': binascii.hexlify(encryptor_aes.nonce).decode('ascii'),
                'nonce_data': binascii.hexlify(encrypted_n).decode('ascii')}
    return jsonify(response), 200

@app.route('/gettranskeypt', methods=['POST'])
def get_trans_key_pat():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400

    required_fields = ['accessor','key','transid']

    if not all(key in values for key in required_fields):
        response = {'message': 'Required data missing!'}

    accessor = values['accessor']
    key = values['key']
    transid = values['transid']
    with open('data/server_bkp.json', mode='r') as f:
        rec = json.load(f)[accessor]
        alpha = rec["alpha"]
        nonce = rec[str(transid)]['nonce']

    encryptor = PKCS1_OAEP.new(RSA.importKey(binascii.unhexlify(key)))
    seskey = binascii.hexlify(Cryptodome.Random.get_random_bytes(16)).decode('ascii')
    enc_ses = encryptor.encrypt(str(seskey).encode('utf8 '))

    encryptor_aes = AES.new(binascii.unhexlify(seskey), AES.MODE_EAX)
    encrypted_a = encryptor_aes.encrypt(str(alpha).encode('utf8 '))
    # encrypted_a = encryptor.encrypt(str(alpha).encode('utf8 '))
    encrypted_n = encryptor_aes.encrypt(str(nonce).encode('utf8 '))
    response = {'seskey': binascii.hexlify(enc_ses).decode('ascii'),
                'alpha': binascii.hexlify(encrypted_a).decode('ascii'),
                'nonce': binascii.hexlify(encryptor_aes.nonce).decode('ascii'),
                'nonce_data': binascii.hexlify(encrypted_n).decode('ascii')}
    return jsonify(response), 200



@app.route('/addperm', methods=['POST'])
def add_perm():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400

    required_fields = ['accessor','nodeid','doctor']

    if not all(key in values for key in required_fields):
        response = {'message': 'Required data missing!'}

    accessor = values['accessor']
    nodeid = values['nodeid']
    doctor = values['doctor']
    if 'updDict' in values:
        updDict = json.load(values['updDict'])
    else:
        updDict = None
    with open('data/server_bkp.json', mode='r') as f:
        data = json.load(f)
        if updDict == None:
            print(data[accessor])
            rec = data[accessor]
            for i in rec:
                if i != 'alpha':
                    if str(nodeid) in rec[i]:
                        rec[i][str(nodeid)].append(doctor)
                    else:
                        rec[i][str(nodeid)] = [doctor]
            data[accessor] = rec
        else:
            for i in updDict:
                for j in updDict[i]:
                    if str(nodeid) in data[i][j]:
                        data[i][j][str(nodeid)].append(doctor)
                    else:
                        data[i][j][str(nodeid)] = [doctor]
    with open('data/server_bkp.json', mode='w') as f:
        json.dump(data, f, indent=4)
    response = {'message': 'Permission granted!'}
    return jsonify(response), 200


@app.route('/create_keys', methods=['POST'])
def create_keys():
    wallet.create_keys()
    if wallet.save_keys():
        global blockchain
        blockchain = Blockchain(wallet.public_key, port, host)
        response = {
            'public_key': wallet.public_key,
            'private_key': wallet.private_key,
        }
        return jsonify(response), 200
    else:
        response = {'message': 'Saving keys failed!', }
        return jsonify(response), 500


@app.route('/load_keys', methods=['GET'])
def load_keys():
    if wallet.load_keys():
        global blockchain
        blockchain = Blockchain(wallet.public_key, port, host)
        response = {
            'public_key': wallet.public_key,
            'private_key': wallet.private_key,
        }
        return jsonify(response), 200
    else:
        response = {'message': 'Loading keys failed!', }
        return jsonify(response), 500



if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=4100)
    parser.add_argument('--host', type=str, default='localhost')
    args = parser.parse_args()
    global host
    port, host = args.port, args.host
    if port == 2:
        unauthenticated.run(host=host, port=port)
    else:
        print(port,type(port))
        wallet = Wallet(port)
        app.run(host=host, port=port)
