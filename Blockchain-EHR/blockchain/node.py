import binascii
import os
import json
import time
import socket
from contextlib import closing
import random
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

from blockchain import Blockchain
from transaction import Transaction
from wallet import Wallet
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.PublicKey import RSA
import threading
import Cryptodome

app = Flask(__name__)
unauthenticated = Flask(__name__)

# enables opening up app to other nodes
CORS(app)
CORS(unauthenticated)
data_proc_key = "30819f300d06092a864886f70d010101050003818d0030818902818100ec204daf19d5b4bb8cbd5b6b31a3770982c1b0694c2487309b0798d568bfb7cc2e447611f5e2b4a49e2b0232ab9db186f4c79962b90290e6f7cc1899f0dd05cd3d37be1c0d263bde3f22a5bdca9f6b3a77c36bb83b9408e6b20e3db413e9068d726c0d1c674e019cd0f46e3346c3bb8da03e02cbebecab759fdb8a99807c3d010203010001"


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


@app.route('/broadcast_transaction', methods=['POST'])
def broadcast_transaction():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400

    required_fields = ['sender', 'patient', 'doctor', 'hospital',
                       'details', 'signature', 'tid', 'timestamp', 'p_pntr', 'd_pntr']

    if not all(key in values for key in required_fields):
        response = {'message': 'Required data missing!'}
        return jsonify(response), 400
    success = blockchain.add_transaction(
        values['patient'], values['sender'], values['doctor'], values['hospital'],
        values['signature'], values['details'], values['tid'], values['timestamp'], values['p_pntr'], values['d_pntr'], is_receiving=True)
    if success:
        response = {
            'message': 'Succesfully broadcasted transaction!',
            'transaction': {
                'sender': values['sender'],
                'patient': values['patient'],
                'doctor': values['doctor'],
                'hospital': values['hospital'],
                'signature': values['signature'],
                'details': values['details'],
                'tid': values['tid'],
                #'nonce': values['nonce'],
                'timestamp': values['timestamp']
            }
        }
        return jsonify(response), 200
    else:
        response = {'message': 'Creating transaction failed!'}
        return jsonify(response), 500





@app.route('/broadcast_block', methods=['POST'])
def broadcast_block():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400
    if 'block' not in values:
        response = {'message': 'Required data missing!'}
        return jsonify(response), 400
    block = values['block']
    if block['index'] == blockchain.get_chain()[-1].index + 1:
        if blockchain.add_block(block):
            response = {'message': 'Block added!'}
            return jsonify(response), 200
        else:
            response = {'message': 'Block seems invalid!'}
            return jsonify(response), 409

    elif block['index'] > blockchain.get_chain()[-1].index:
        blockchain.resolve_conflicts = True
        response = {'message': 'Blockchain differs from local chain!'}
        return jsonify(response), 200
    else:
        response = {'message': 'Blockchain is shorter, block not added!'}
        return jsonify(response), 409


@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    if wallet.private_key == None:
        response = {'message': 'No wallet set up!'}
        return jsonify(response), 400
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400
    required_fields = ['patient', 'doctor', 'hospital', 'details', 'timestamp', 'tid']
    if not all(f in values for f in required_fields):
        response = {'message': 'Required data missing!'}
        return jsonify(response), 400
    encryptor = PKCS1_OAEP.new(RSA.importKey(binascii.unhexlify(data_proc_key)))
    decrypted = values["details"]
    seskey = binascii.hexlify(Cryptodome.Random.get_random_bytes(16)).decode('ascii')
    enc_ses = encryptor.encrypt(str(seskey).encode('utf8 '))

    encryptor_aes = AES.new(binascii.unhexlify(seskey), AES.MODE_EAX)

    decrypted["medicine"] = binascii.hexlify(encryptor_aes.encrypt(str(decrypted["medicine"]).encode('utf8 '))).decode(
        'ascii')
    decrypted["test"] = binascii.hexlify(encryptor_aes.encrypt(str(decrypted["test"]).encode('utf8 '))).decode(
        'ascii')
    decrypted["comments"] = binascii.hexlify(encryptor_aes.encrypt(str(decrypted["comments"]).encode('utf8 '))).decode(
        'ascii')
    decrypted["create_time"] = binascii.hexlify(
        encryptor_aes.encrypt(str(decrypted["create_time"]).encode('utf8 '))).decode(
        'ascii')
    # sent data to data processing server to encrypt
    api_url = "http://127.0.0.1:4200/encrypt"
    pr = {'patient': values['patient'], 'transid': values['tid'],'nodeid':wallet.node_id, 'doctor': values["doctor"], 'details':decrypted,'seskey':binascii.hexlify(enc_ses).decode('ascii'),
                'nonce':binascii.hexlify(encryptor_aes.nonce).decode('ascii')}
    # response = json.loads(requests.post(api_url, json=pr).text)
    response = requests.post(api_url, json=pr)
    if response.status_code == 400:
        response = {'error': "Patient does not exist, register the patient first!!"}
        return jsonify(response), 400
    response = json.loads(response.text)
    details = response['encrypted']
    #nonce = response['nonce']

    #details, nonce = wallet.enc_transaction(values["details"], values['patient'],  values['tid'], values["doctor"])
    patient = values['patient']
    doctor = values['doctor']
    hospital = values['hospital']
    timestamp = values['timestamp']
    tid = values['tid']
    signature = wallet.sign_transaction(wallet.public_key, patient, doctor, hospital, details)

    api_url = "http://127.0.0.1:4200/getpointer"
    pr = {'accessor': patient, 'acc_type':'patient','open':blockchain.is_open()}
    response = json.loads(requests.post(api_url, json=pr).text)
    p_pntr = {'t_index':response['t_index'], 'b_index':response['b_index']}
    pr = {'accessor': doctor, 'acc_type': 'doctor','open':blockchain.is_open()}
    response = json.loads(requests.post(api_url, json=pr).text)
    d_pntr = {'t_index':response['t_index'], 'b_index':response['b_index']}

    success = blockchain.add_transaction(
        patient, wallet.public_key, doctor, hospital, signature, details, tid, timestamp,p_pntr, d_pntr)
    if success:
        api_url = "http://127.0.0.1:4200/updatepointer"
        pr = {'patient': patient, 'doctor':doctor,'blockid':blockchain.chain_len(),'transid':blockchain.is_open()-1}
        respons = requests.post(api_url, json=pr)
        response = {
            'message': 'Succesfully added transaction!',
            'transaction': {
                'sender': wallet.public_key,
                'patient': patient,
                'doctor': doctor,
                'hospital': hospital,
                'signature': signature,
                'details': details,
                #'nonce': nonce,
                'timestamp': timestamp,
                'ptindex':p_pntr,
                'dcindex':d_pntr
            }
        }
        return jsonify(response), 200
    else:
        response = {'message': 'Creating transaction failed!'}
        return jsonify(response), 500




@app.route('/mine', methods=['POST'])
def mine():
    if blockchain.resolve_conflicts:
        response = {'message': 'Resolve conflicts first,block not added!'}
        return jsonify(response), 409

    block, block_id = blockchain.mine_block()

    if block == 0:
        response = {'message': 'No transactions to add!'}
        # return jsonify(response), 500
        print(response)
    elif block != None:
        dt = block.__dict__.copy()
        dt['transactions'] = [tx.__dict__ for tx in dt['transactions']]
        respons = requests.post("http://127.0.0.1:4200/updatepntrfile", json={})
        # api_url = "http://127.0.0.1:4200/updatepointer"
        # pr = {'details': dt['transactions'],'blockid':block_id}
        # respons = requests.post(api_url, json=pr)
        response = {
            'message': 'Block added succesfully!',
            'block': dt
        }
        print(response)
    else:
        response = {
            'message': 'Adding block failed!',
            'is_wallet_setup': wallet.public_key != None
        }
        print(response)


@app.route('/resolve_conflicts', methods=['POST'])
def resolve_conflicts():
    replaced = blockchain.resolve()
    if replaced:
        response = {'message': 'Chain was replaced!'}
        return jsonify(response), 400
    else:
        response = {'message': 'Local chain kept!'}
    return jsonify(response), 200


@app.route('/get_opentransactions', methods=['GET'])
def get_opentransactions():
    transactions = blockchain.get_open_transactions()
    dict_tx = [tx.__dict__ for tx in transactions]
    return jsonify(dict_tx), 200


def d(tx, doctor):
    transaction = tx.__dict__.copy()
    finaltransaction = {}
    # if transaction['sender'] == sender:
    if transaction['doctor'] == doctor:
        finaltransaction = transaction
        finaltransaction['details'] = wallet.dec_transaction(transaction["details"], transaction['patient'],
                                                             transaction['tid'], transaction['doctor'])#, transaction['nonce'])
    return finaltransaction
def conv_dict(details):
    res = []
    details= details[1:-1]
    for sub in details.split("',"):
        sub=sub.replace("'","")
        if ':' in sub:
            res.append(map(str.strip, sub.split(':', 1)))
    res = dict(res)
    return res


yha = 0
def fu(tx, accessor, acc_type, doctor):
    global yha
    yha+=1
    print(yha)
    transaction = tx#.__dict__.copy()
    finaltransaction = {}
    if transaction[acc_type] == accessor:
        finaltransaction = transaction

        api_url = "http://127.0.0.1:4200/decrypt"
        pr = {'patient': transaction['patient'], 'transid': transaction['tid'], 'doctor': doctor,
              'details': transaction["details"], 'nodeid':wallet.node_id, 'node_key':wallet.public_key}
        respons = requests.post(api_url, json=pr)
        response = json.loads(respons.text)
        seskey = binascii.unhexlify(response['seskey'])
        nonce = binascii.unhexlify(response['nonce'])
        if respons.status_code == 500:
            finaltransaction['details'] = {}
            finaltransaction['details']['medicine'] = response['decrypted']
            finaltransaction['details']['test'] = response['decrypted']
            finaltransaction['details']['comments'] =response['decrypted']
            finaltransaction['details']['create_time'] =response['decrypted']
        else:
            finaltransaction['details'] = response['decrypted']
            decryptor = PKCS1_OAEP.new(RSA.importKey(
                binascii.unhexlify(wallet.private_key)))
            decrypted = decryptor.decrypt(seskey)
            ses_key = binascii.unhexlify(decrypted)
            decryptor_aes = AES.new(ses_key, AES.MODE_EAX, nonce)
            # decrypted = decryptor.decrypt(values['details'])
            # details = binascii.unhexlify(decrypted)


            finaltransaction['details']['medicine'] = decryptor_aes.decrypt(binascii.unhexlify(finaltransaction['details']['medicine'])).decode('utf-8')
            finaltransaction['details']['test'] = decryptor_aes.decrypt(binascii.unhexlify(finaltransaction['details']['test'])).decode('utf-8')
            finaltransaction['details']['comments'] = decryptor_aes.decrypt(binascii.unhexlify(finaltransaction['details']['comments'])).decode('utf-8')
            finaltransaction['details']['create_time'] = decryptor_aes.decrypt(binascii.unhexlify(finaltransaction['details']['create_time'])).decode('utf-8')

            # encryptor = PKCS1_OAEP.new(RSA.importKey(binascii.unhexlify(wallet.private_key)))
            #
            # transaction["details"]["medicine"] = binascii.hexlify(
            #     encryptor.encrypt(str(transaction["details"]["medicine"]).encode('utf8 '))).decode('ascii')
            # transaction["details"]["test"] = binascii.hexlify(
            #     encryptor.encrypt(str(transaction["details"]["test"]).encode('utf8 '))).decode('ascii')
            # transaction["details"]["comments"] = binascii.hexlify(
            #     encryptor.encrypt(str(transaction["details"]["comments"]).encode('utf8 '))).decode('ascii')
            # transaction["details"]["create_time"] = binascii.hexlify(
            #     encryptor.encrypt(str(transaction["details"]["create_time"]).encode('utf8 '))).decode('ascii')

            # finaltransaction['details'] = wallet.dec_transaction(transaction["details"], transaction['patient'], transaction['tid'], doctor, transaction['nonce'])
    return finaltransaction
def fu_patient(tx, accessor, acc_type):
    transaction = tx#.__dict__.copy()
    finaltransaction = {}
    print(transaction[acc_type],accessor)
    if transaction[acc_type] == accessor:
        finaltransaction = transaction
        api_url = "http://127.0.0.1:4200/decrypt_patient"
        pr = {'patient': accessor, 'transid': transaction['tid'], 'doctor': transaction["doctor"],
              'details': transaction["details"], 'node_key':wallet.public_key} #'nonce': transaction['nonce'],
        response = json.loads(requests.post(api_url, json=pr).text)
        finaltransaction['details'] = response['decrypted']
        seskey = binascii.unhexlify(response['seskey'])
        nonce = binascii.unhexlify(response['nonce'])
        decryptor = PKCS1_OAEP.new(RSA.importKey(
            binascii.unhexlify(wallet.private_key)))
        decrypted = decryptor.decrypt(seskey)
        ses_key = binascii.unhexlify(decrypted)
        decryptor_aes = AES.new(ses_key, AES.MODE_EAX, nonce)
        # decrypted = decryptor.decrypt(values['details'])
        # details = binascii.unhexlify(decrypted)

        finaltransaction['details']['medicine'] = decryptor_aes.decrypt(
            binascii.unhexlify(finaltransaction['details']['medicine'])).decode('utf-8')
        finaltransaction['details']['test'] = decryptor_aes.decrypt(
            binascii.unhexlify(finaltransaction['details']['test'])).decode('utf-8')
        finaltransaction['details']['comments'] = decryptor_aes.decrypt(
            binascii.unhexlify(finaltransaction['details']['comments'])).decode('utf-8')
        finaltransaction['details']['create_time'] = decryptor_aes.decrypt(
            binascii.unhexlify(finaltransaction['details']['create_time'])).decode('utf-8')
        #finaltransaction['details'] = wallet.dec_transaction_patient(transaction["details"], accessor, transaction['tid'], transaction["doctor"], transaction['nonce'])
    return finaltransaction

def fu_doctor(tx, accessor, acc_type):
    transaction = tx#.__dict__.copy()
    finaltransaction = {}
    if transaction[acc_type] == accessor:
        finaltransaction = transaction
        api_url = "http://127.0.0.1:4200/decrypt"
        pr = {'patient': transaction['patient'], 'transid': transaction['tid'], 'doctor': accessor,
              'details': transaction["details"],  'nodeid': wallet.node_id, 'node_key':wallet.public_key} #'nonce': transaction['nonce'],
        respons = requests.post(api_url, json=pr)
        response = json.loads(respons.text)
        seskey = binascii.unhexlify(response['seskey'])
        nonce = binascii.unhexlify(response['nonce'])
        if respons.status_code == 500:
            finaltransaction['details'] = {}
            finaltransaction['details']['medicine'] = response['decrypted']
            finaltransaction['details']['test'] = response['decrypted']
            finaltransaction['details']['comments'] = response['decrypted']
            finaltransaction['details']['create_time'] = response['decrypted']
        else:
            finaltransaction['details'] = response['decrypted']
            decryptor = PKCS1_OAEP.new(RSA.importKey(
                binascii.unhexlify(wallet.private_key)))
            decrypted = decryptor.decrypt(seskey)
            ses_key = binascii.unhexlify(decrypted)
            decryptor_aes = AES.new(ses_key, AES.MODE_EAX, nonce)
            # decrypted = decryptor.decrypt(values['details'])
            # details = binascii.unhexlify(decrypted)

            finaltransaction['details']['medicine'] = decryptor_aes.decrypt(
                binascii.unhexlify(finaltransaction['details']['medicine'])).decode('utf-8')
            finaltransaction['details']['test'] = decryptor_aes.decrypt(
                binascii.unhexlify(finaltransaction['details']['test'])).decode('utf-8')
            finaltransaction['details']['comments'] = decryptor_aes.decrypt(
                binascii.unhexlify(finaltransaction['details']['comments'])).decode('utf-8')
            finaltransaction['details']['create_time'] = decryptor_aes.decrypt(
                binascii.unhexlify(finaltransaction['details']['create_time'])).decode('utf-8')

        finaltransaction['details'] = response['decrypted']
        # finaltransaction['details'] = wallet.dec_transaction(transaction["details"], transaction['patient'], transaction['tid'], accessor, transaction['nonce'])
    return finaltransaction

def fu_hospital(tx, accessor, acc_type):
    transaction = tx.__dict__.copy()
    finaltransaction = {}
    if str(transaction[acc_type]) == str(accessor):
        finaltransaction = transaction
        finaltransaction['details'] = wallet.dec_transaction(transaction["details"], transaction['patient'], transaction['tid'], transaction["doctor"] )#, transaction['nonce'])
    return finaltransaction


@app.route('/patientchain', methods=['POST'])
def get_patient_chain():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400
    required_fields = ['patient', 'doctor']
    if not all(f in values for f in required_fields):
        response = {'message': 'Required data missing!'}
        return jsonify(response), 400
    patient = values['patient']
    doctor = values['doctor']

    chain_snapshot = blockchain.get_chain()
    dict_chain = [block.__dict__.copy() for block in chain_snapshot]

    api_url = "http://127.0.0.1:4200/getpointer"
    pr = {'accessor': patient, 'acc_type': 'patient','open':0}
    response = json.loads(requests.post(api_url, json=pr).text)
    t_index = response['t_index']
    b_index = response['b_index']
    new_chain = [{"transactions":[]}]
    while b_index!=-1:
        tx = dict_chain[b_index]['transactions'][t_index].__dict__.copy()
        new_chain[0]["transactions"].append(fu(tx, patient, 'patient', doctor))
        b_index = tx['p_pntr']['b_index']
        t_index = tx['p_pntr']['t_index']
    # for dt in dict_chain:
    #     dt['transactions'] = [fu(tx, patient, 'patient', doctor) for tx in dt['transactions']]
    #     # work on this duplicate
    #     [dt['transactions'].remove(tx)
    #      for tx in dt['transactions'] if tx == {}]
    #
    # new_chain = [item for item in dict_chain if item['transactions'] != []]

    return jsonify(new_chain), 200


@app.route('/patient_specific_chain', methods=['POST'])
def get_patient_chain_patient():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400
    required_fields = ['patient']
    if not all(f in values for f in required_fields):
        response = {'message': 'Required data missing!'}
        return jsonify(response), 400
    patient = values['patient']
    # doctor = values['doctor']

    chain_snapshot = blockchain.get_chain()
    dict_chain = [block.__dict__.copy() for block in chain_snapshot]

    api_url = "http://127.0.0.1:4200/getpointer"
    pr = {'accessor': patient, 'acc_type': 'patient','open':0}
    response = json.loads(requests.post(api_url, json=pr).text)
    t_index = response['t_index']
    b_index = response['b_index']
    new_chain = [{"transactions": []}]
    while b_index != -1:
        tx = dict_chain[b_index]['transactions'][t_index].__dict__.copy()
        # new_chain[0]["transactions"].append(fu(tx, patient, 'patient', doctor))
        new_chain[0]["transactions"].append(fu_patient(tx, patient, 'patient'))
        b_index = tx['p_pntr']['b_index']
        t_index = tx['p_pntr']['t_index']

    return jsonify(new_chain), 200

@app.route('/doctorchain', methods=['POST'])
def get_doctor_chain():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400
    required_fields = ['doctor']
    if not all(f in values for f in required_fields):
        response = {'message': 'Required data missing!'}
        return jsonify(response), 400
    doctor = values['doctor']

    chain_snapshot = blockchain.get_chain()
    dict_chain = [block.__dict__.copy() for block in chain_snapshot]

    api_url = "http://127.0.0.1:4200/getpointer"
    pr = {'accessor': doctor, 'acc_type': 'doctor','open':0}
    response = json.loads(requests.post(api_url, json=pr).text)
    t_index = response['t_index']
    b_index = response['b_index']
    new_chain = [{"transactions": []}]
    while b_index != -1:
        tx = dict_chain[b_index]['transactions'][t_index].__dict__.copy()
        new_chain[0]["transactions"].append(fu_doctor(tx, doctor, 'doctor'))
        b_index = tx['d_pntr']['b_index']
        t_index = tx['d_pntr']['t_index']

    # for dt in dict_chain:
    #     dt['transactions'] = [fu_doctor(tx, doctor, 'doctor') for tx in dt['transactions']]
    #     # work on this duplicate
    #     [dt['transactions'].remove(tx)
    #      for tx in dt['transactions'] if tx == {}]
    #     [dt['transactions'].remove(tx)
    #      for tx in dt['transactions'] if tx == {}]
    #
    # new_chain = [item for item in dict_chain if item['transactions'] != []]

    return jsonify(new_chain), 200

@app.route('/hospitalchain', methods=['POST'])
def get_hospital_chain():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400
    required_fields = ['hospital']
    if not all(f in values for f in required_fields):
        response = {'message': 'Required data missing!'}
        return jsonify(response), 400
    hospital = values['hospital']

    chain_snapshot = blockchain.get_chain()
    dict_chain = [block.__dict__.copy() for block in chain_snapshot]

    for dt in dict_chain:
        dt['transactions'] = [fu_hospital(tx, hospital, 'hospital') for tx in dt['transactions']]
        # work on this duplicate
        [dt['transactions'].remove(tx)
         for tx in dt['transactions'] if tx == {}]
        [dt['transactions'].remove(tx)
         for tx in dt['transactions'] if tx == {}]

    new_chain = [item for item in dict_chain if item['transactions'] != []]

    return jsonify(new_chain), 200

@app.route('/addperm', methods=['POST'])
def add_permission():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400
    required_fields = ['acc_type', 'accessor', 'nodeid','doctor']
    if not all(f in values for f in required_fields):
        response = {'message': 'Required data missing!'}
        return jsonify(response), 400
    acc_type = values['acc_type']
    accessor = values['accessor']
    nodeid = values['nodeid']
    doctor = values['doctor']

    if acc_type == 'patient':
        api_url = "http://127.0.0.1:4100/addperm"
        pr = {'accessor': accessor, 'nodeid':nodeid, 'doctor':doctor}
        response = requests.post(api_url, json=pr)
        #Wallet.add_perm(accessor, nodeid, doctor)
    else:
        chain_snapshot = blockchain.get_chain()
        dict_chain = [block.__dict__.copy() for block in chain_snapshot]

        updDict = {}
        for dt in dict_chain:
            for tx in dt['transactions']:
                transaction = tx.__dict__.copy()
                if transaction[acc_type] == accessor:
                    if transaction['patient'] in updDict:
                        updDict[transaction['patient']].append(transaction['tid'])
                    else:
                        updDict[transaction['patient']] = [transaction['tid']]
        api_url = "http://127.0.0.1:4100/addperm"
        pr = {'accessor': accessor, 'nodeid': nodeid, 'doctor': doctor, 'updDict':jsonify(updDict)}
        response = requests.post(api_url, json=pr)
        #Wallet.add_perm(accessor, nodeid, doctor, updDict)

    return jsonify(response.text), response.status_code

# @app.route('/doctorchain', methods=['POST'])
# def get_doctor_chain():
#     values = request.get_json()
#     if not values:
#         response = {'message': 'No data found!'}
#         return jsonify(response), 400
#     required_fields = ['sender']
#     if not all(f in values for f in required_fields):
#         response = {'message': 'Required data missing!'}
#         return jsonify(response), 400
#     sender = values['sender']
#     doctor = values['doctor']
#
#     chain_snapshot = blockchain.get_chain()
#     dict_chain = [block.__dict__.copy() for block in chain_snapshot]
#
#     for dt in dict_chain:
#         dt['transactions'] = [d(tx, doctor) for tx in dt['transactions']]
#         # work on this duplicate
#         [dt['transactions'].remove(tx)
#          for tx in dt['transactions'] if tx == {}]
#         [dt['transactions'].remove(tx)
#          for tx in dt['transactions'] if tx == {}]
#
#     new_chain = [item for item in dict_chain if item['transactions'] != []]
#     return jsonify(new_chain), 200


@app.route('/chain', methods=['GET'])
def get_chain():
    chain_snapshot = blockchain.get_chain()
    dict_chain = [block.__dict__.copy() for block in chain_snapshot]
    # why this for loop required?
    for dt in dict_chain:
        dt['transactions'] = [tx.__dict__ for tx in dt['transactions']]

    return jsonify(dict_chain), 200


@app.route('/add_node', methods=['POST'])
def add_node():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400
    if 'node' not in values:
        response = {'message': 'No nodes found!'}
        return jsonify(response), 400

    node = values['node']
    blockchain.add_peer_node(node)

    response = {
        'message': 'Node added successfully!',
        'nodes': blockchain.get_peer_nodes()
    }
    return jsonify(response), 200


@app.route('/remove_node/<node_url>', methods=['DELETE'])
def remove_node(node_url):
    if node_url == '' or node_url == None:
        response = {'message': 'No node found!'}
        return jsonify(response), 400

    blockchain.remove_peer_node(node_url)
    response = {
        'message': 'Node removed successfully!',
    }
    return jsonify(response), 200


@app.route('/get_nodes', methods=['GET'])
def get_nodes():
    nodes = blockchain.get_peer_nodes()
    response = {'nodes': nodes}
    return jsonify(response), 200


@app.route('/verifymine', methods=['POST'])
def verify_mine():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400
    node = values['node']
    if str(node) == miner:
        return jsonify({"comment":"go ahead"}), 200

@app.route('/synctime', methods=['POST'])
def sync_time():
    global peerSyncCt, miner, peerList, ownTime, timeList
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400
    node = values['node']
    tim = values['time']
    timeList[peerList.index(str(node))] = tim
    peerSyncCt += 1
    if peerSyncCt==len(peerList):
        print(args.port,peerList,timeList)
        res = [-1]
        # initially sets itself as miner
        miner = str(args.port)
        thread = threading.Thread(target=mine_proc, args=(peerSyncCt, str(args.port), peerList, ownTime, timeList, res))
        thread.start()
        thread.join()
        miner = res[0]
        print(miner)
    return jsonify({"comment":"go ahead"}), 200

def mine_proc(peerSyncCt, nodeid, peerList, ownTime, timeList, res):

    minTime = min(timeList)
    minNode = peerList[timeList.index(minTime)]
    if (minNode==nodeid):
        time.sleep(minTime * 60)
        flag = True
        for i in peerList:
            api_url = "http://127.0.0.1:{}/verifymine".format(i)
            response = requests.post(api_url, json={'node': args.port})
            stat = response.status_code
            if stat != 200:
                flag = False
        if flag:
            mine()

        def send_reset(peer):
            requests.post("http://127.0.0.1:{}/resetclock".format(peer))
        threads = [None] * len(peerList)
        for i in range(len(peerList)):
            peer = peerList[i]
            threads[i] = threading.Thread(target=send_reset, args=(peer,))
            threads[i].start()
    res[0] = minNode
    return True

@app.route('/resetclock', methods=['POST'])
def reset_clock():
    global peerSyncCt, miner, peerList, ownTime, timeList
    peerSyncCt = 0
    miner = -1
    timeList = [-1 for _ in peerList]
    ownTime = random.randint(2,8)
    def sync_t(port,tim,i):
            api_url = "http://127.0.0.1:{}/synctime".format(i)
            response = requests.post(api_url, json={'node': port, 'time': tim})
            stat = response.status_code
    threads = [None] * len(peerList)
    for i in range(len(peerList)):
        threads[i] = threading.Thread(target=sync_t, args=(args.port, ownTime, peerList[i]))
        threads[i].start()
    return jsonify({"yay":"started"}),200



if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=5005)
    parser.add_argument('--host', type=str, default='localhost')
    args = parser.parse_args()
    global host
    port, host = args.port, args.host
    if port == 2:
        unauthenticated.run(host=host, port=port)
    else:
        timeList = []
        peerList = []
        with open('data/peers.txt') as f:
            peerList = f.read().split('\n')
        # if str(args.port) in peerList:
        #     peerList.remove(str(args.port))
        ownTime = -1
        peerSyncCt = 0
        miner = -1
        print(port,type(port))
        wallet = Wallet(port)
        blockchain = Blockchain(wallet.public_key, port, host)
        app.run(host=host, port=port)
