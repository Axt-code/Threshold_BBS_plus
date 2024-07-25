from py_ecc.bls12_381 import *
from hashlib import sha256 
from binascii import hexlify, unhexlify
import random
import time
from helper import * 
import json

from web3 import Web3

# web3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID'))
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8888", request_kwargs = {'timeout' : 300}))

contract_address = "0xFFD53914Ef6B17f8746752d3Da4E1aaa57049761"
validator_address = "0x21f7D9eb24A476ed35bE1dea8Ec6677C8e4fDCAB"
tf = json.load(open('./build/contracts/user.json'))
contract_address = Web3.toChecksumAddress(contract_address)
user_contract = w3.eth.contract(address = contract_address, abi = tf['abi'])


request_filter = user_contract.events.send_msg.createFilter(fromBlock="0x0", toBlock='latest')
user_contract.functions.sample(5).transact({'from':validator_address})
time.sleep(5)
storage_log = request_filter.get_new_entries()
print(storage_log[0]["args"]["iddd"])




