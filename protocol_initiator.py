import jsonpickle
import json
from helper import *


from datetime import datetime
import time
from py_ecc.bn128 import *
import argparse
import os
import pickle
import socket
import threading
from web3 import Web3
import random
import numpy as np
import hashlib
from collections import defaultdict
from typing import List, Tuple
import asyncio
from mpyc.runtime import mpc
#No address to change:
# python3 ProtocolInitiator_AnonymousCredentials.py --title "Loan Credential" --address 0xE279a5e0DEb02eDe68876bea8206EeFb2Ab0E96C --validator-addresses 0x444D3aa9426Ca8e339d607bF53262A8B524B844e 0x2D0B894312087b3BF55e4432871b6FD3CC8c180A 0x5126e167868d403dba7DbC5a28bA0e5ACbb086C0 --opener-addresses 0x202870f3671F1d6B401693FBcF66082781D1958F 0x34aB8f91ef8524a9eCF47D2eC6ab1DBdC3a2D704 0xdedCA5790B8899dA5168a4D34b171A8294D0Fb5F --rpc-endpoint "http://127.0.0.1:7545"

parser = argparse.ArgumentParser(description="Anonymous Credentials registration")
parser.add_argument("--title", type=str, default = None, required = True, help= "This is the title of the Anonymous Credential.")
parser.add_argument("--name", type=str, default = None, required = True,  help= "The name of organisation giving the Anonymous Credential")
parser.add_argument("--req-ip", type=str, default = '127.0.0.1', required = False,  help= "The ip at which organisation is running.")
parser.add_argument("--req-port", type=str, default = None, required = True,  help= "The port on which organisation is running.")
parser.add_argument("--address", type=str, default = None, required = True,  help= "The blockchain address on which organization is running.")
parser.add_argument('--validator-addresses', nargs='+', help='The blockchain addresses of the validators for the Anonymous Credential issuance.', required=True)
parser.add_argument("--rpc-endpoint", type=str, default = None, required = True,  help= "The node rpc endpoint through which a client is connected to blockchain network.")
parser.add_argument('--dependency', nargs='+', help='The Vcerts on which the Anonymous Credential issuance depends on.', required=False)
parser.add_argument("--params-address", type=str, default = None, required = True,  help= "The blockchain address at which params contract is deployed.")

args = parser.parse_args() 

nv = int(input("Enter the value for nv: "))
tv = int(input("Enter the value for tv: "))
q = int(input("Enter the value for q: "))

mode = 0o777
root_dir = "./ROOT"

try:
	os.mkdir(root_dir, mode = mode)
except FileExistsError as e:
	pass

register_path = os.path.join(root_dir, "ac_register.pickle")
encoding_types = os.path.join(root_dir, "encoding_type_map.pickle")


try:
	f = open(encoding_types,'rb')
	encoding_type_map = pickle.load(f)
	f.close()
except FileNotFoundError as e:
	f = open(encoding_types,'wb') 
	encoding_type_map = {"1": type("string"), "2": type(1), "3": type(datetime.now())}
	pickle.dump(encoding_type_map, f)
	f.close()

try:
	f = open(register_path,'rb')
	RegisteredList = pickle.load(f)
	f.close()
	register = { "title":args.title, "ip" : args.req_ip, "port":args.req_port, "dependency": [] }
	if args.dependency != None:
		register = { "title":args.title, "ip" :args.req_ip,  "port":args.req_port, "dependency": args.dependency }
	RegisteredList.append(register)
	f = open(register_path,'wb')
	pickle.dump(RegisteredList, f)
	f.close()
except FileNotFoundError as e:
	f = open(register_path,'wb')
	register = { "title":args.title, "ip" : args.req_ip, "port":args.req_port, "dependency": [] }
	if args.dependency != None:
		register = { "title":args.title, "ip" : args.req_ip, "port":args.req_port, "dependency": args.dependency }
	pickle.dump([register], f)
	f.close()

def uploadAddresses(address, filename):
	file_path = os.path.join(root_dir, filename)
	f = open(file_path,'wb')
	pickle.dump(address, f)
	f.close()

#print(args.params_address)
#print("Displaying Output as: % s" % args.params_address)
uploadAddresses(args.params_address, "params_address.pickle")
# uploadAddresses(args.request_address, "request_address.pickle")
# uploadAddresses(args.issue_address, "issue_address.pickle")
# uploadAddresses(args.opening_address, "opening_address.pickle")


# //////////////////////////////////////////////////////////////////////////////////////////////////////
issuer_id=0
H_values_G1=[]

class Commitments:
    def __init__(self, commitments: List[bytes]):
        self.commitments = commitments

class Issuer:
    def __init__(self, id, shares_and_salts: List[Tuple[int, bytes]]):
        self.id = id
        self.own_shares_and_salts = shares_and_salts
        self.other_commitments = {}
        self.other_shares = defaultdict(list)

    @staticmethod
    def commit(rng, id, batch_size):
        shares_and_salts = [(random.getrandbits(256), rng.bytes(32)) for _ in range(batch_size)]
        commitments = Issuer.compute_commitments(shares_and_salts)
        return Issuer(id, shares_and_salts), Commitments(commitments)

    def receive_commitment(self, sender_id, commitments):
        if self.id == sender_id:
            raise ValueError("Sender ID cannot be the same as self ID")
        if sender_id in self.other_commitments:
            raise ValueError("Already have commitment from participant")
        if len(self.own_shares_and_salts) != len(commitments.commitments):
            print(f"length of own shares and salts {len(self.own_shares_and_salts)}")
            print(f"length of commitments {len(commitments)}")
            raise ValueError("Incorrect number of commitments")
        self.other_commitments[sender_id] = commitments

    def receive_shares(self, sender_id, shares_and_salts: List[Tuple[int, bytes]]):
        if self.id == sender_id:
            raise ValueError("Sender ID cannot be the same as self ID")
        if sender_id not in self.other_commitments:
            raise ValueError("Missing commitment from participant")
        if sender_id in self.other_shares:
            raise ValueError("Already have shares from participant")
        if len(self.own_shares_and_salts) != len(shares_and_salts):
            raise ValueError("Incorrect number of shares")
        expected_commitments = Issuer.compute_commitments(shares_and_salts)
        print(f"expected_commitemnts: {expected_commitments}")
        print(f"self.other_commitments[sender_id].commitments {self.other_commitments[sender_id].commitments}")
        # if expected_commitments != self.other_commitments[sender_id].commitments:
        #     raise ValueError("Incorrect commitment")
        self.other_shares[sender_id] = [share for share, _ in shares_and_salts]

    def compute_joint_randomness(self):
        joint_randomness = []
        for i in range(len(self.own_shares_and_salts)):
            sum = self.own_shares_and_salts[i][0]
            for shares in self.other_shares.values():
                sum += shares[i]
            joint_randomness.append(sum)
        return joint_randomness

    def has_commitment_from(self, id):
        return id in self.other_commitments

    def has_shares_from(self, id):
        return id in self.other_shares

    def has_shares_from_all_who_committed(self):
        return len(self.other_shares) == len(self.other_commitments)

    @staticmethod
    def compute_commitments(shares_and_salts):
        return [hash_function(share, salt) for share, salt in shares_and_salts]

def hash_function(share: int, salt: bytes):
    data = share.to_bytes(32, 'big') + salt
    return hashlib.sha3_256(data).digest()

def deterministic_random_oracle(input_value, L):
    
    input_str = str(input_value)
    length = len(input_str)
    
   
    seed = int(hashlib.sha256(input_str.encode()).hexdigest(), 16)
    
    
    random.seed(seed)
   
    random_values = []
    for _ in range(L):
        random_value = ''.join(random.choices('0123456789', k=length))
        random_values.append(random_value)
    
    return random_values

async def mpc_setup():
    await mpc.start()
    global issuer_id
    global H_values_G1
    print(f"mpc.pid: {mpc.pid}")
    issuer_id=mpc.pid
    print(f"issuer_id: {issuer_id}")
    print(f"mpc.parties: {mpc.parties}")
    np_rng = np.random.default_rng()
    

    issuer, commitments = Issuer.commit(np_rng, issuer_id, 1)
    print(f"Commitments: {commitments.commitments}")
    print(f"Issuer_id: {issuer.id}")
    print(f"share: {issuer.own_shares_and_salts}")
    #commitments_share = await mpc.transfer(Commitments, commitments.commitments, senders =issuer_id)
    commitments_share = await mpc.transfer(commitments.commitments)
    print(f"commitments_share: {commitments_share}")
   # shares = await mpc.transfer(commitments_share)
   # print(f"shares: {shares}")
   # print(f"commitment length: {len(commitments_share)}")
    for party_id in range(len(mpc.parties)):
        if party_id != issuer_id:
            issuer.receive_commitment(party_id, Commitments(commitments_share[party_id]))
            
            #shares_and_salts = [(random.getrandbits(256), np_rng.bytes(32)) for _ in range(1)]
            #issuer.receive_shares(party_id, shares_and_salts)
    shares = await mpc.transfer(issuer.own_shares_and_salts)
    print(f"shares: {shares}")
    for party_id in range(len(mpc.parties)):
        if party_id != issuer_id:
            issuer.receive_shares(party_id, shares[party_id])

    H0 = issuer.compute_joint_randomness()
    print(f"Issuer {issuer_id} Joint Randomness: {H0}")

    await mpc.shutdown()

    # // generate L values
    L = 10
    H_values = deterministic_random_oracle(H0[0], L)
    H_values.insert(0, H0[0])
    
    for idx, value in enumerate(H_values):
    	# print(f"Random value H: {idx}: {value}")
        H_values_G1.append(hashG1(str(value).encode('utf-8')))

mpc.run(mpc_setup())

print(f"issuer_id: {issuer_id}")

# //////////////////////////////////////////////////////////////////////////////////////////////////////





def getRegister(register_path):
	f = open(register_path,'rb')
	RegisteredList = pickle.load(f)
	f.close()
	for register in RegisteredList:
		if register["title"] == args.title:
			return register
	print("No such Anonymous Credentials.")
	return None

register = getRegister(register_path)
ip, dependency =  register["ip"], register["dependency"]


def getParamsAddress():
	file_path = os.path.join(root_dir, "params_address.pickle")
	f = open(file_path,'rb')
	params_address = pickle.load(f)
	f.close()
	return params_address

def getRequestAddress():
	file_path = os.path.join(root_dir, "request_address.pickle")
	f = open(file_path,'rb')
	request_address = pickle.load(f)
	f.close()
	return request_address

def getIssueAddress():
	file_path = os.path.join(root_dir, "issue_address.pickle")
	f = open(file_path,'rb')
	issue_address = pickle.load(f)
	f.close()
	return issue_address

def encodeG2(g2):
	return (g2[0].coeffs[0].n, g2[0].coeffs[1].n, g2[1].coeffs[0].n, g2[1].coeffs[1].n)

def decodeToG2(encoded_g2):
	return (FQ2([encoded_g2[0], encoded_g2[1],]), FQ2([encoded_g2[2], encoded_g2[3],]),)

def encodeG2List(g2_list):
  encoded_g2_list = []
  for g2 in g2_list:
    if g2 is not None:
      encoded_g2_list.append(encodeG2(g2))
    else:
      encoded_g2_list.append(None)
  return encoded_g2_list

def decodeToG2List(encoded_g2_list):
  g2_list = []
  for encoded_g2 in encoded_g2_list:
    if encoded_g2 is not None:
      g2_list.append(decodeToG2(encoded_g2))
    else:
      g2_list.append(None)
  return g2_list

def encodeVk(vk):
  g2, g2x, g1y, g2y = vk
  encoded_vk = []
  encoded_vk.append(encodeG2(g2))
  encoded_vk.append(encodeG2(g2x))
  encoded_vk.append(g1y)
  encoded_g2y = []
  for i in range(len(g2y)):
    encoded_g2y.append(encodeG2(g2y[i]))
  encoded_vk.append(encoded_g2y)
  return tuple(encoded_vk)

def encodeVkList(vks):
  encoded_vks = []
  for vk in vks:
    if vk is not None:
      encoded_vks.append(encodeVk(vk))
    else:
      encoded_vks.append(None)
  return encoded_vks

def decodeVkList(encoded_vks):
  vks = []
  for encoded_vk in encoded_vks:
    if encoded_vk is not None:
      vks.append(decodeVk(encoded_vk))
    else:
      vks.append(None)
  return vks

def decodeVk(encoded_vk):
  encoded_g2, encoded_g2x, g1y, encoded_g2y = encoded_vk
  vk = []
  vk.append(decodeToG2(encoded_g2))
  vk.append(decodeToG2(encoded_g2x))
  vk.append(g1y)
  g2y = []
  for i in range(len(encoded_g2y)):
    g2y.append(decodeToG2(encoded_g2y[i]))
  vk.append(g2y)
  return tuple(vk)

# def loadOpenerKeys(title):
# 	ac_path = os.path.join(root_dir, title)
# 	ac_file_path = os.path.join(ac_path, "openerKeys.pickle")
# 	f = open(ac_file_path,'rb')
# 	json_pk = pickle.load(f)
# 	f.close()
# 	encoded_opks = jsonpickle.decode(json_pk)
# 	opks = decodeToG2List(encoded_opks)
# 	return opks

def loadValidatorKeys(title):
	ac_path = os.path.join(root_dir, title)
	ac_file_path = os.path.join(ac_path, "validatorKeys.pickle")
	f = open(ac_file_path,'rb')
	json_pk = pickle.load(f)
	f.close()
	encoded_vks = jsonpickle.decode(json_pk)
	vks = decodeVkList(encoded_vks)
	return vks

def getIncludeIndexes(title, _dependency):
	ac_path = os.path.join(root_dir, title)
	ac_file_path = os.path.join(ac_path, "include_indexes.pickle")
	f = open(ac_file_path,'rb')
	include_indexes = pickle.load(f)
	f.close()
	_include_indexes = []
	for key in _dependency:
		_include_indexes.append(include_indexes[key])
	return _include_indexes

params_address       = getParamsAddress()


# w3 = Web3(Web3.WebsocketProvider(args.rpc_endpoint, websocket_timeout = 100))
w3 = Web3(Web3.HTTPProvider(args.rpc_endpoint, request_kwargs = {'timeout' : 300}))

# ------------------------------------------------------------------------
# Params.sol
# All the TTP system parameters and Aggregated Validators Key

tf = json.load(open('./build/contracts/Params.json'))
params_address = Web3.toChecksumAddress(params_address)
params_contract = w3.eth.contract(address = params_address, abi = tf['abi']) 



# -------------------------------------------------------------------------

# def getTotalOpeners(title):
# 	ac_path = os.path.join(root_dir, title)
# 	ac_file_path = os.path.join(ac_path, "no.pickle")
# 	f = open(ac_file_path,'rb')
# 	no = pickle.load(f)
# 	f.close()
# 	return no

# def getThresholdOpeners(title):
# 	ac_path = os.path.join(root_dir, title)
# 	ac_file_path = os.path.join(ac_path, "to.pickle")
# 	f = open(ac_file_path,'rb')
# 	to = pickle.load(f)
# 	f.close()
# 	return to

def getTotalValidators(title):
	ac_path = os.path.join(root_dir, title)
	ac_file_path = os.path.join(ac_path, "nv.pickle")
	f = open(ac_file_path,'rb')
	nv = pickle.load(f)
	f.close()
	return nv

def getThresholdValidators(title):
	ac_path = os.path.join(root_dir, title)
	ac_file_path = os.path.join(ac_path, "tv.pickle")
	f = open(ac_file_path,'rb')
	tv = pickle.load(f)
	f.close()
	return tv

def getTotalAttributes(title):
	ac_path = os.path.join(root_dir, title)
	ac_file_path = os.path.join(ac_path, "q.pickle")
	f = open(ac_file_path,'rb')
	q = pickle.load(f)
	f.close()
	return q

# def downloadParams(title):
# 	ac_path = os.path.join(root_dir, title)
# 	ac_file_path = os.path.join(ac_path, "params.pickle")
# 	f = open(ac_file_path,'rb')
# 	json_params = pickle.load(f)
# 	params = jsonpickle.decode(json_params)
# 	f.close()
# 	return params

def getCombinations(title):
	ac_path = os.path.join(root_dir, title)
	ac_file_path = os.path.join(ac_path, "combinations.pickle")
	f = open(ac_file_path,'rb')
	combinations = pickle.load(f)
	f.close()
	return combinations

# nv = getTotalValidators(args.title)
# tv = getThresholdValidators(args.title)
# # no = getTotalOpeners(args.title)
# # to = getThresholdOpeners(args.title) 
# q = getTotalAttributes(args.title)

# nv = 3
# tv = 2
# q = 2

def encodeG2(g2):
	return (g2[0].coeffs[0].n, g2[0].coeffs[1].n, g2[1].coeffs[0].n, g2[1].coeffs[1].n)

def decodeToG2(encoded_g2):
	return (FQ2([encoded_g2[0], encoded_g2[1],]), FQ2([encoded_g2[2], encoded_g2[3],]),)

def encodeG2List(g2_list):
  encoded_g2_list = []
  for g2 in g2_list:
    if g2 is not None:
      encoded_g2_list.append(encodeG2(g2))
    else:
      encoded_g2_list.append(None)
  return encoded_g2_list

def decodeToG2List(encoded_g2_list):
  g2_list = []
  for encoded_g2 in encoded_g2_list:
    if encoded_g2 is not None:
      g2_list.append(decodeToG2(encoded_g2))
    else:
      g2_list.append(None)
  return g2_list

def encodeVk(vk):
  g2, g2x, g1y, g2y = vk
  encoded_vk = []
  encoded_vk.append(encodeG2(g2))
  encoded_vk.append(encodeG2(g2x))
  encoded_vk.append(g1y)
  encoded_g2y = []
  for i in range(len(g2y)):
    encoded_g2y.append(encodeG2(g2y[i]))
  encoded_vk.append(encoded_g2y)
  return tuple(encoded_vk)

def encodeVkList(vks):
  encoded_vks = []
  for vk in vks:
    if vk is not None:
      encoded_vks.append(encodeVk(vk))
    else:
      encoded_vks.append(None)
  return encoded_vks

def decodeVkList(encoded_vks):
  vks = []
  for encoded_vk in encoded_vks:
    if encoded_vk is not None:
      vks.append(decodeVk(encoded_vk))
    else:
      vks.append(None)
  return vks

def decodeVk(encoded_vk):
  encoded_g2, encoded_g2x, g1y, encoded_g2y = encoded_vk
  vk = []
  vk.append(decodeToG2(encoded_g2))
  vk.append(decodeToG2(encoded_g2x))
  vk.append(g1y)
  g2y = []
  for i in range(len(encoded_g2y)):
    g2y.append(decodeToG2(encoded_g2y[i]))
  vk.append(g2y)
  return tuple(vk)


# params = downloadParams(args.title)
params = setup(q, args.title)

(sk, vk) = ttp_keygen(params, tv, nv)
aggregate_vk = agg_key(params, vk)

print(f"type of sk: {type(sk)}")

for s in sk:
	print(f"sk key : {s}\n")

print(f"type of vk: {type(vk)}")

for v in vk:
	print(f"vk key : {v}\n")

encoded_vks = encodeVkList(vk)
encoded_aggregate_vk = encodeVk(aggregate_vk)

ac_path = os.path.join(root_dir, args.title)

os.makedirs(ac_path, exist_ok=True)

ac_file_path = os.path.join(ac_path, "vk.pickle")
f = open(ac_file_path,'wb')
json_vk = jsonpickle.encode(encoded_vks)
pickle.dump(json_vk, f)
f.close()

ac_file_path = os.path.join(ac_path, "aggregate_vk.pickle")
f = open(ac_file_path,'wb')
json_aggregate_vk = jsonpickle.encode(encoded_aggregate_vk)
pickle.dump(json_aggregate_vk, f)
f.close()

# -------------------------------------------------------------
# port = 3003
port = args.req_port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((ip, int(port)))        
print (args.name + " binded to %s" %(port))
s.listen(10)    
print (args.name +" is listening")
key_request_count = 0
while key_request_count < nv:
	try:
		c, addr = s.accept()
		validator = c.recv(8192).decode() # validator:1
		v_id = int(validator.split(":")[1])
		keys = (encoded_vks[v_id-1], sk[v_id-1])
		keysJSON = jsonpickle.encode(keys)
		c.send(keysJSON.encode())
		print("sent keys to Validator : ", str(v_id))
		key_request_count += 1
		c.close()
	except Exception as e:
		print(e)
		s.shutdown(socket.SHUT_RDWR)
		s.close()

# ---------------------------------------------------------------

organization_address = args.address
# -------------------------- Validators key generation  -----------------------------

_, o, g1, hs, g2, e = params	
encoded_hs = [(hs[i][0].n, hs[i][1].n) for i in range(len(hs))]
(_, alpha, g1_beta, beta)= aggregate_vk

encoded_alpha = ((alpha[0].coeffs[1].n, alpha[0].coeffs[0].n), (alpha[1].coeffs[1].n, alpha[1].coeffs[0].n))
encoded_beta = [((beta[i][0].coeffs[1].n,beta[i][0].coeffs[0].n),(beta[i][1].coeffs[1].n,beta[i][1].coeffs[0].n)) for i in range(len(beta))]
encoded_g1_beta = [(g1_beta[i][0].n, g1_beta[i][1].n) for i in range(len(g1_beta))]
# encoded_opk = [[[opks[i][0].coeffs[1].n, opks[i][0].coeffs[0].n],[opks[i][1].coeffs[1].n, opks[i][1].coeffs[0].n]] for i in range(no)]

# ---------------------  setting params to contract (Params.sol) --------------------------

# validator params
#  string[][] _combinations

encoded_include_indexes = getIncludeIndexes(args.title, dependency)

combinations = getCombinations(args.title)

def downloadSchema(title):
	ca_path = os.path.join(root_dir, title)
	ca_file_path = os.path.join(ca_path, "schema.pickle")
	f = open(ca_file_path,'rb')
	schema = pickle.load(f)
	f.close()
	return schema

def downloadEncoding(title):
	ca_path = os.path.join(root_dir, title)
	ca_file_path = os.path.join(ca_path, "encoding.pickle")
	f = open(ca_file_path,'rb')
	encoding = pickle.load(f)
	f.close()
	return encoding

def downloadSchemaOrder(title):
	ca_path = os.path.join(root_dir, title)
	ca_file_path = os.path.join(ca_path, "schemaOrder.pickle")
	f = open(ca_file_path,'rb')
	schemaOrder = pickle.load(f)
	f.close()
	return schemaOrder

schema = downloadSchema(args.title)
schemaOrder = downloadSchemaOrder(args.title)
encoding = downloadEncoding(args.title)
public_m_encoding = []
for key in schemaOrder:
	if schema[key]['visibility'] == 'public':
		public_m_encoding.append(encoding[key])


tx_hash = params_contract.functions.set_params(args.title, encoded_alpha, encoded_g1_beta, encoded_beta, combinations, dependency, encoded_include_indexes, public_m_encoding, H_values_G1 ).transact({'from': organization_address})
w3.eth.waitForTransactionReceipt(tx_hash)



# opener_addresses = args.opener_addresses
# validator_addresses = args.validator_addresses

# for validator_addr in validator_addresses:
# 	tx_hash = issue_contract.functions.addIssuer(validator_addr).transact({'from':organization_address})
# 	w3.eth.waitForTransactionReceipt(tx_hash)