import binascii
import os
import json
from time import time
import socket
from contextlib import closing

import Cryptodome
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

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

auth_pub_key ="30819f300d06092a864886f70d010101050003818d0030818902818100e9bc5cf03251b8288afa309740db28f950f1eb33ffc4d99a996c743c96a0217781401b6d890cffb232f48473bd54a815d84bdff7d047643cea3cd1b4abfbcabf02875cd6179cc81508846be54d1f7d49d9ec0903a81cfd4110020444d32f5951bbdb8070a45490e2d1c6d4dd1b0add93024c09403109a7e2e84ed0440735fd730203010001"

@app.route('/encrypt', methods=['POST'])
def enc_transaction():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400

    required_fields = ['patient','doctor','transid','nodeid','details']

    if not all(key in values for key in required_fields):
        response = {'message': 'Required data missing!'}
        return jsonify(response), 400

    patient = values['patient']
    doctor = values['doctor']
    transid = values['transid']
    seskey = binascii.unhexlify(values['seskey'])
    nonce = binascii.unhexlify(values['nonce'])
    decryptor = PKCS1_OAEP.new(RSA.importKey(
        binascii.unhexlify(wallet.private_key)))
    decrypted = decryptor.decrypt(seskey)
    ses_key = binascii.unhexlify(decrypted)
    decryptor_aes = AES.new(ses_key, AES.MODE_EAX, nonce)

    # decrypted = decryptor.decrypt(values['details'])
    # details = binascii.unhexlify(decrypted)

    values['details']['medicine'] = decryptor_aes.decrypt(
        binascii.unhexlify(values['details']['medicine'])).decode('utf-8')
    values['details']['test'] = decryptor_aes.decrypt(
        binascii.unhexlify(values['details']['test'])).decode('utf-8')
    values['details']['comments'] = decryptor_aes.decrypt(
        binascii.unhexlify(values['details']['comments'])).decode('utf-8')
    values['details']['create_time'] = decryptor_aes.decrypt(
        binascii.unhexlify(values['details']['create_time'])).decode('utf-8')

    details = values['details']
    nodeid = values['nodeid']

    api_url = "http://127.0.0.1:4100/createtranskey"
    pr = {'accessor': patient, 'transid': transid, 'nodeid': nodeid, 'doctor': doctor, 'key':wallet.public_key}
    # enc = binascii.unhexlify(json.loads(requests.post(api_url, json=pr).text)['alpha'])
    response = requests.post(api_url, json=pr)
    if response.status_code == 400:
        response = {'error': "Patient does not exist, register the patient first!!"}
        return jsonify(response), 400
    seskey = binascii.unhexlify(json.loads(response.text)['seskey'])
    nonce = binascii.unhexlify(json.loads(response.text)['nonce'])
    enc = binascii.unhexlify(json.loads(response.text)['alpha'])


    decryptor = PKCS1_OAEP.new(RSA.importKey(
            binascii.unhexlify(wallet.private_key)))
    decrypted = decryptor.decrypt(seskey)
    ses_key = binascii.unhexlify(decrypted)
    decryptor_aes = AES.new(ses_key, AES.MODE_EAX, nonce)
    decrypted = decryptor_aes.decrypt(enc)
    key = binascii.unhexlify(decrypted)
    # key = self.crt_trans_key(patient, transid, self.node_id, doctor)
    encrypter = AES.new(key, AES.MODE_EAX)
    h = (str(details)).encode('utf8 ')
    encrypted = encrypter.encrypt(h)
    response = {'encrypted':binascii.hexlify(encrypted).decode('ascii')}

    encryptor = PKCS1_OAEP.new(RSA.importKey(binascii.unhexlify(auth_pub_key)))
    hex = (str(binascii.hexlify(encrypter.nonce).decode('ascii'))).encode('utf-8')
    encrypted = encryptor.encrypt(hex)
    api_url = "http://127.0.0.1:4100/pushnonce"
    pr = {'accessor': patient, 'transid': transid, 'nonce':binascii.hexlify(encrypted).decode('ascii')}
    # enc = binascii.unhexlify(json.loads(requests.post(api_url, json=pr).text)['alpha'])
    _ = requests.post(api_url, json=pr)


    return jsonify(response), 200
def conv_dict(details):
    res = []
    details= details[1:-1]
    for sub in details.split("',"):
        sub=sub.replace("'","")
        if ':' in sub:
            res.append(map(str.strip, sub.split(':', 1)))
    res = dict(res)
    return res

@app.route('/decrypt', methods=['POST'])
def dec_transaction():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400

    required_fields = ['patient', 'doctor', 'transid', 'nodeid', 'details']

    if not all(key in values for key in required_fields):
        response = {'message': 'Required data missing!'}

    patient = values['patient']
    doctor = values['doctor']
    transid = values['transid']
    details = values['details']
    #nonce = values['nonce']
    nodeid = values['nodeid']
    node_key = values['node_key']
    api_url = "http://127.0.0.1:4100/gettranskey"
    pr = {'accessor': patient, 'transid': transid, 'nodeid': nodeid, 'doctor': doctor,'key': wallet.public_key}
    response = requests.post(api_url, json=pr)
    if response.status_code == 500:
        response = {'decrypted': 'Restricted record!!!'}
        return jsonify(response), 500
    else:
        enc_a = binascii.unhexlify(json.loads(response.text)['alpha'])
        enc_n = binascii.unhexlify(json.loads(response.text)['nonce_data'])
        seskey = binascii.unhexlify(json.loads(response.text)['seskey'])
        nonce = binascii.unhexlify(json.loads(response.text)['nonce'])

        decryptor = PKCS1_OAEP.new(RSA.importKey(
            binascii.unhexlify(wallet.private_key)))

        decrypted = decryptor.decrypt(seskey)
        ses_key = binascii.unhexlify(decrypted)
        decryptor_aes = AES.new(ses_key, AES.MODE_EAX, nonce)

        decrypted = decryptor_aes.decrypt(enc_a)
        key = binascii.unhexlify(decrypted)
        decrypted = decryptor_aes.decrypt(enc_n)
        nonce = binascii.unhexlify(decrypted)
    print(key)
    decrypter = AES.new(key, AES.MODE_EAX, nonce)
    h = binascii.unhexlify(details)
    decrypted = decrypter.decrypt(h)
    decrypted = conv_dict(decrypted.decode('utf-8'))

    encryptor = PKCS1_OAEP.new(RSA.importKey(binascii.unhexlify(node_key)))
    seskey = binascii.hexlify(Cryptodome.Random.get_random_bytes(16)).decode('ascii')
    enc_ses = encryptor.encrypt(str(seskey).encode('utf8 '))

    encryptor_aes = AES.new(binascii.unhexlify(seskey), AES.MODE_EAX)

    decrypted["medicine"] = binascii.hexlify(encryptor_aes.encrypt(str(decrypted["medicine"]).encode('utf8 '))).decode('ascii')
    decrypted["test"] = binascii.hexlify(encryptor_aes.encrypt(str(decrypted["test"]).encode('utf8 '))).decode(
        'ascii')
    decrypted["comments"] = binascii.hexlify(encryptor_aes.encrypt(str(decrypted["comments"]).encode('utf8 '))).decode(
        'ascii')
    decrypted["create_time"] = binascii.hexlify(encryptor_aes.encrypt(str(decrypted["create_time"]).encode('utf8 '))).decode(
        'ascii')

    response = {'decrypted': decrypted,
                'seskey':binascii.hexlify(enc_ses).decode('ascii'),
                'nonce':binascii.hexlify(encryptor_aes.nonce).decode('ascii')}#decrypted.decode('utf-8')}
    return jsonify(response), 200

@app.route('/decrypt_patient', methods=['POST'])
def dec_transaction_pt():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400

    required_fields = ['patient','doctor','transid','details']

    if not all(key in values for key in required_fields):
        response = {'message': 'Required data missing!'}

    patient = values['patient']
    doctor = values['doctor']
    transid = values['transid']

    details = values['details']
    #nonce = values['nonce']
    node_key = values['node_key']

    api_url = "http://127.0.0.1:4100/gettranskeypt"
    pr = {'accessor': patient, 'transid': transid,'key':wallet.public_key}
    response = requests.post(api_url, json=pr)
    enc_a = binascii.unhexlify(json.loads(response.text)['alpha'])
    enc_n = binascii.unhexlify(json.loads(response.text)['nonce_data'])
    seskey = binascii.unhexlify(json.loads(response.text)['seskey'])
    nonce = binascii.unhexlify(json.loads(response.text)['nonce'])

    decryptor = PKCS1_OAEP.new(RSA.importKey(
        binascii.unhexlify(wallet.private_key)))

    decrypted = decryptor.decrypt(seskey)
    ses_key = binascii.unhexlify(decrypted)
    decryptor_aes = AES.new(ses_key, AES.MODE_EAX, nonce)

    decrypted = decryptor_aes.decrypt(enc_a)
    key = binascii.unhexlify(decrypted)
    decrypted = decryptor_aes.decrypt(enc_n)
    nonce = binascii.unhexlify(decrypted)

    decrypter = AES.new(key, AES.MODE_EAX, nonce)
    h = binascii.unhexlify(details)
    decrypted = decrypter.decrypt(h)
    decrypted = conv_dict(decrypted.decode('utf-8'))

    encryptor = PKCS1_OAEP.new(RSA.importKey(binascii.unhexlify(node_key)))
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

    response = {'decrypted': decrypted, 'seskey':binascii.hexlify(enc_ses).decode('ascii'), 'nonce':binascii.hexlify(encryptor_aes.nonce).decode('ascii')}  # decrypted.decode('utf-8')}
    return jsonify(response), 200

@app.route('/updatepointer', methods=['POST'])
def update_pointers():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400

    required_fields = ['patient','doctor','blockid','transid']

    if not all(key in values for key in required_fields):
        response = {'message': 'Required data missing!'}

    patient = values['patient']
    doctor = values['doctor']
    block_id = values['blockid']
    trans_id = values['transid']

    data = {}
    with open('data/patient_pointer_new.json', mode='r') as f:
        data = json.load(f)
        data[patient] = {}
        data[patient]['tindex'] = trans_id
        data[patient]['bindex'] = block_id

    with open('data/patient_pointer_new.json', mode='w') as f:
        json.dump(data, f, indent=4)

    data = {}
    with open('data/doctor_pointer_new.json', mode='r') as f:
        data = json.load(f)
        data[doctor] = {}
        data[doctor]['tindex'] = trans_id
        data[doctor]['bindex'] = block_id

    with open('data/doctor_pointer_new.json', mode='w') as f:
        json.dump(data, f, indent=4)

    response = {'comment': 'pointers updated!!!'}  # decrypted.decode('utf-8')}
    return jsonify(response), 200


@app.route('/updatepntrfile', methods=['POST'])
def update_file():

    with open('data/patient_pointer_new.json', mode='r') as f:
        data = json.load(f)
    with open('data/patient_pointer.json', mode='w') as f:
        json.dump(data, f, indent=4)
    with open('data/doctor_pointer_new.json', mode='r') as f:
        data = json.load(f)
    with open('data/doctor_pointer.json', mode='w') as f:
        json.dump(data, f, indent=4)

    response = {'comment': 'file updated!!!'}  # decrypted.decode('utf-8')}
    return jsonify(response), 200

# @app.route('/updatepointer', methods=['POST'])
# def update_pointers():
#     values = request.get_json()
#     if not values:
#         response = {'message': 'No data found!'}
#         return jsonify(response), 400
#
#     required_fields = ['details','blockid']
#
#     if not all(key in values for key in required_fields):
#         response = {'message': 'Required data missing!'}
#
#     transactions = values['details']
#     block_id = values['blockid']
#
#     data = {}
#     with open('data/patient_pointer.json', mode='r') as f:
#         data = json.load(f)
#         for i in range(len(transactions)):
#             data[transactions[i]['patient']] = {}
#             data[transactions[i]['patient']]['tindex'] = i
#             data[transactions[i]['patient']]['bindex'] = block_id
#
#     with open('data/patient_pointer.json', mode='w') as f:
#         json.dump(data, f, indent=4)
#
#     data = {}
#     with open('data/doctor_pointer.json', mode='r') as f:
#         data = json.load(f)
#         for i in range(len(transactions)):
#             data[transactions[i]['doctor']] = {}
#             data[transactions[i]['doctor']]['tindex'] = i
#             data[transactions[i]['doctor']]['bindex'] = block_id
#
#     with open('data/doctor_pointer.json', mode='w') as f:
#         json.dump(data, f, indent=4)
#
#     response = {'comment': 'pointers updated!!!'}  # decrypted.decode('utf-8')}
#     return jsonify(response), 200

@app.route('/getpointer', methods=['POST'])
def get_pointers():
    values = request.get_json()
    if not values:
        response = {'message': 'No data found!'}
        return jsonify(response), 400

    required_fields = ['accessor','acc_type','open']

    if not all(key in values for key in required_fields):
        response = {'message': 'Required data missing!'}

    accessor = values['accessor']
    acc_type = values['acc_type']
    openflag = "" if values['open']==0 else "_new"
    if acc_type=='doctor':
        with open('data/doctor_pointer'+openflag+'.json', mode='r') as f:
            data = json.load(f)
            if accessor in data:
                t_in = data[accessor]['tindex']
                b_in = data[accessor]['bindex']
            else:
                t_in = -1
                b_in = -1
    elif acc_type=='patient':
        with open('data/patient_pointer'+openflag+'.json', mode='r') as f:
            data = json.load(f)
            if accessor in data:
                t_in = data[accessor]['tindex']
                b_in = data[accessor]['bindex']
            else:
                t_in = -1
                b_in = -1


    response = {'t_index': t_in, 'b_index':b_in}  # decrypted.decode('utf-8')}
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
    parser.add_argument('-p', '--port', type=int, default=4200)
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
