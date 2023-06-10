import json

import requests
from Cryptodome.PublicKey import RSA

from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256
import Cryptodome.Random
from Cryptodome.Cipher import PKCS1_OAEP, AES

import binascii

class Wallet:
    def __init__(self, node_id):
        self.private_key = None
        self.public_key = None
        self.node_id = node_id

    def create_keys(self):
        private_key, public_key = self.generate_keys()
        self.private_key = private_key
        self.public_key = public_key

    def save_keys(self):
        if self.private_key != None and self.public_key != None:
            try:
                with open('data/wallet-{}.json'.format(self.node_id), mode='w') as f:
                    data = {}
                    data["public_key"] = self.public_key
                    data["private_key"] = self.private_key
                    json.dump(data, f, indent=4)
                return True
            except (IOError, IndexError):
                print('Saving wallet failed')
                return False

    def load_keys(self):
        try:
            # keys = loadkeys(self.node_id)
            with open('data/wallet-{}.json'.format(self.node_id), mode='r') as f:
                keys = json.load(f)
                public_key = keys["public_key"]
                private_key = keys["private_key"]
                self.public_key = public_key
                self.private_key = private_key
            return True
        except (IOError, IndexError):
            print('Loading wallet failed')
            return False

    def generate_keys(self):
        private_key = RSA.generate(1024, Cryptodome.Random.new().read)
        public_key = private_key.publickey()
        return (
            binascii.hexlify(private_key.exportKey(
                format='DER')).decode('ascii'),
            binascii.hexlify(public_key.exportKey(
                format='DER')).decode('ascii')
        )

    def sign_transaction(self, sender, patient, doctor, hospital, details):
        signer = PKCS1_v1_5.new(RSA.importKey(
            binascii.unhexlify(self.private_key)))
        h = SHA256.new((str(sender) + str(patient) + str(doctor) + str(hospital) +
                        str(details)).encode('utf8 '))
        signature = signer.sign(h)
        return binascii.hexlify(signature).decode('ascii')

    # def enc_transaction(self, details, patient, transid, doctor):
    #     api_url = "http://127.0.0.1:4100/createtranskey"
    #     pr = {'accessor': patient, 'transid':transid, 'nodeid':self.node_id, 'doctor':doctor}
    #     key = binascii.unhexlify(json.loads(requests.post(api_url, json=pr).text)['alpha'])
    #     # key = self.crt_trans_key(patient, transid, self.node_id, doctor)
    #     encrypter = AES.new(key, AES.MODE_EAX)
    #     h = (str(details)).encode('utf8 ')
    #     encrypted = encrypter.encrypt(h)
    #     return binascii.hexlify(encrypted).decode('ascii'), binascii.hexlify(encrypter.nonce).decode('ascii')
    #
    # def dec_transaction(self, details, patient, transid, doctor, nonce):
    #     print(patient , type(patient),len(patient))
    #     print(doctor, type(doctor), len(doctor))
    #     api_url = "http://127.0.0.1:4100/gettranskey"
    #     pr = {'accessor': patient, 'transid': transid, 'nodeid': self.node_id, 'doctor': doctor}
    #     response = requests.post(api_url, json=pr)
    #     if response.status_code == 500:
    #         return details
    #     else:
    #         key = binascii.unhexlify(json.loads(response.text)['alpha'])
    #     print(key)
    #     decrypter = AES.new(key, AES.MODE_EAX, binascii.unhexlify(nonce))
    #     h = binascii.unhexlify(details)
    #     decrypted = decrypter.decrypt(h)
    #     return decrypted.decode('utf-8')
    #
    # def dec_transaction_patient(self, details, patient, transid, doctor, nonce):
    #     print(patient , type(patient),len(patient))
    #     print(doctor, type(doctor), len(doctor))
    #     api_url = "http://127.0.0.1:4100/gettranskeypt"
    #     pr = {'accessor': patient}
    #     key = json.loads(requests.post(api_url, json=pr).text)
    #     key = binascii.unhexlify(key['alpha'])
    #
    #     decrypter = AES.new(key, AES.MODE_EAX, binascii.unhexlify(nonce))
    #     h = binascii.unhexlify(details)
    #     decrypted = decrypter.decrypt(h)
    #     return decrypted.decode('utf-8')

    @staticmethod
    def verify_transaction(transaction):
        public_key = RSA.importKey(binascii.unhexlify(transaction.sender))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA256.new((str(transaction.sender) + str(transaction.patient) + str(transaction.doctor) + str(transaction.hospital) +
                        str(transaction.details)).encode('utf8 '))
        return verifier.verify(h, binascii.unhexlify(transaction.signature))

    # @staticmethod
    # def get_trans_key(accessor, transid, nodeid, doctor):
    #     with open('data/server_bkp.json', mode='r') as f:
    #         rec = json.load(f)[accessor]
    #
    #         # if accessor in rec[str(transid)]:
    #         if str(nodeid) in rec[str(transid)] and doctor in rec[str(transid)][str(nodeid)]:
    #             alpha = binascii.unhexlify(rec["alpha"])
    #         else:
    #             return False
    #         # h = (str(alpha)).encode('utf8 ')#SHA256.new()str(nonce)
    #         return alpha
    #
    # @staticmethod
    # def get_trans_key_patient(accessor, transid, nodeid, doctor):
    #     with open('data/server_bkp.json', mode='r') as f:
    #         rec = json.load(f)[accessor]
    #         alpha = binascii.unhexlify(rec["alpha"])
    #         return alpha
    #
    # @staticmethod
    # def crt_trans_key(accessor, transid, nodeid, doctor):
    #     data = {}
    #     with open('data/server_bkp.json', mode='r') as f:
    #         data = json.load(f)
    #         data[accessor][transid] = {str(nodeid) : [doctor]}
    #         alpha = binascii.unhexlify(data[accessor]["alpha"])
    #     with open('data/server_bkp.json', mode='w') as f:
    #         json.dump(data, f, indent=4)
    #     return alpha
    #
    # @staticmethod
    # def crt_new_key(accessor):
    #     data = {}
    #     with open('data/server_bkp.json', mode='r') as f:
    #         data = json.load(f)
    #         alpha = Cryptodome.Random.get_random_bytes(16)
    #         data[accessor] = {
    #                 'alpha': binascii.hexlify(alpha).decode('ascii')
    #             }
    #     with open('data/server_bkp.json', mode='w') as f:
    #         json.dump(data, f, indent=4)
    #     print('done')
    #     return alpha
    #
    # @staticmethod
    # def add_perm(accessor, nodeid, doctor, updDict=None):
    #     with open('data/server_bkp.json', mode='r') as f:
    #         data = json.load(f)
    #         if updDict == None:
    #             rec = data[accessor]
    #             for i in rec:
    #                 if i != 'alpha':
    #                     if str(nodeid) in rec[i]:
    #                         rec[i][str(nodeid)].append(doctor)
    #                     else:
    #                         rec[i][str(nodeid)] = [doctor]
    #             data[accessor] = rec
    #         else:
    #             for i in updDict:
    #                 for j in updDict[i]:
    #                     if str(nodeid) in data[i][j]:
    #                         data[i][j][str(nodeid)].append(doctor)
    #                     else:
    #                         data[i][j][str(nodeid)] = [doctor]
    #     with open('data/server_bkp.json', mode='w') as f:
    #         json.dump(data, f, indent=4)
    #     return True