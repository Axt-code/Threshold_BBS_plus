from py_ecc.bls12_381 import *
from hashlib import sha256 
from binascii import hexlify, unhexlify
import random
import time

import web3
from helper import * 
import json
from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545", request_kwargs = {'timeout' : 300}))


contract_address = "".join(open('SC_output.txt').readlines()[99]).strip()
user_address = "0x359139786D9dC16c9B6f1eb1a378147819F0b234"

with open('./build/contracts/user.json') as f:
    tf = json.load(f)
# user_contract = Web3.toChecksumAddress(contract_address)
user_contract = w3.eth.contract(address = contract_address, abi = tf['abi'])

title="user"

sid = Web3.keccak(text='example_sid')  # Generate a 32-byte hash for sid
sigid = Web3.keccak(text='example_sigid')  # Generate a 32-byte hash for sigid
message = 'This is an example message'  # Example message

def broadcast_sig_req(sid, sigid, message):
    tx_hash = user_contract.functions.broadcastSigReq(sid, sigid, message).transact({'from':user_address})
    receipt = w3.eth.waitForTransactionReceipt(tx_hash, timeout=300)

    if receipt.status == 1:
        print("Transaction was successful")
    else:
        print("Transaction failed")
#     # user_contract.functions.sample(5).transact({'from':user_address})

def listen_broadcast_sig_req():
    time.sleep(5)
    request_filter = user_contract.events.SigReqBroadcast.createFilter(fromBlock="0x0", toBlock='latest')
    storage_log = request_filter.get_all_entries()
    print(storage_log[0])



broadcast_sig_req(sid, sigid, message)
listen_broadcast_sig_req()



# def PrepareCredRequest(params, aggr_vk, to, no, opk, prevParams, all_attr, include_indexes, public_m=[]):
#     private_m = []
#     for i in range(len(all_attr)):
#         for j in range(len(all_attr[i])):
#             if include_indexes[i][j] == 1:
#                 private_m.append(int(all_attr[i][j]))

#     assert len(private_m) > 0
#     (G, o, g1, hs, g2, e) = params
#     attributes = private_m + public_m
#     assert len(attributes) <= len(hs)
#     # build commitment
#     rand = random.randint(2, o)#generates random number 
#     cm = add(multiply(g1, rand), ec_sum([multiply(hs[i], attributes[i]) for i in range(len(attributes))]))
#     # build El Gamal encryption
#     h = hashG1(to_binary256(cm))
#     os = [random.randint(2, o) for _ in range(len(private_m))]#os is a "private_m" length random number array
#     commitments = [add(multiply(g1, os[i]), multiply(h, private_m[i])) for i in range(len(private_m))]
#     # pi_s = make_pi_s(params, commitments, cm, os, rand, public_m, private_m, all_attr, prevParams, include_indexes)
#     # # build proofs
#     # # pi_s = make_pi_s(params, gamma, c, cm, k, r, public_m, private_m)
#     # # Lambda = (cm, c, pi_s)
#     # # opening information
#     # # generate polynomials to hide private attributes (m polynomials of degree 'to')
#     # P = [[random.randint(2, o) for _ in range(0, to)] for _ in range(len(private_m))]
#     # for i in range(len(private_m)):
#     #     P[i][0] = private_m[i]
#     # #generate shares s[i] contains shares to ne shared with opener 'i'
#     # s = [[poly_eval(Pj,i) % o for Pj in P] for i in range(1,no+1)]
#     # hidden_P = [[multiply(h, P[i][j]) for j in range(1, to)] for i in range(len(private_m))]

#     # _, _, _, beta = aggr_vk
#     # r = [random.randint(2, o) for _ in range(no)]
#     # C = [(multiply(g2, r[i]), (add(multiply(opk[i], r[i]), ec_sum([multiply(beta[j], s[i][j]) for j in range(len(private_m))])))) for i in range(no)]
#     # Aw, Bw, pi_o = make_pi_o(params, cm, C, r, s, aggr_vk, opk)
    
#     # h_r = [multiply(h, ri) for ri in r]
#     # b_o = [multiply(beta[i], os[i]) for i in range(len(os))] 

#     # Lambda = (cm, commitments, pi_s, hidden_P, C, pi_o, Aw, Bw, h_r, b_o)
#     return os




# Message, sigid

# Commitment, sigid, proof