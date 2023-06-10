from collections import OrderedDict


class Transaction():
    def __init__(self, sender, patient, doctor, hospital, signature, details, tid, timestamp,p_pntr, d_pntr):
        self.sender = sender
        self.patient = patient
        self.doctor = doctor
        self.hospital = hospital
        self.details = details
        self.timestamp = timestamp
        self.signature = signature
        self.tid = tid
        self.p_pntr = p_pntr
        self.d_pntr = d_pntr
        #self.nonce = nonce

    # create ordered dict to help in generating guess in valid proof
    def to_ordered_dict(self):
        return OrderedDict([
            ('sender', self.sender),
            ('patient', self.patient),
            ('details', self.details)
        ])

    def __repr__(self):
        return str(self.__dict__)

