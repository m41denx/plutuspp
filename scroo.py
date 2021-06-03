import os
import hashlib
import binascii
import codecs
import ecdsa
import time
import multiprocessing
from datetime import datetime

max_keys=32

################################# KEYGENERATION #################################
def base58(address_hex): #Implemented
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros and convert hex to decimal
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add '1' for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

def keygen(num_keys):
    keys = []
    for i in range(num_keys):
        private = os.urandom(32).hex()
        #+++
        #private="48C1D149B4D11CA63EC45D1D3DBB654EF30AB7B236C55C80A356509A20412C8C"
        ## PUBLIC UNCOMP
        #+++
        public = b'04'+codecs.encode(ecdsa.SigningKey.from_string(codecs.decode(private, 'hex'), curve=ecdsa.SECP256k1).verifying_key.to_string(), 'hex').upper()
        public_key_bytes = codecs.decode(public, 'hex')

        ## PUBLIC UNCOMP ADDRESS

        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        network_byte = b'00'
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        checksum = sha256_2_hex[:8]
        address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
        address = base58(address_hex)

        ## PUBLIC COMPD
        private_hex = codecs.decode(private, 'hex')
        # Get ECDSA public key
        key = ecdsa.SigningKey.from_string(private_hex, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        # Get X from the key (first half)
        key_string = key_hex.decode('utf-8')
        half_len = len(key_hex) // 2
        key_half = key_hex[:half_len]
        # Add bitcoin byte: 0x02 if the last digit is even, 0x03 if the last digit is odd
        last_byte = int(key_string[-1], 16)
        bitcoin_byte = b'02' if last_byte % 2 == 0 else b'03'
        public_key_comp = bitcoin_byte + key_half

        ## PUBLIC COMPD ADDR
        public_comp_bytes = codecs.decode(public_key_comp, 'hex')
        sha256_bpk = hashlib.sha256(public_comp_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        network_byte = b'00'
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        checksum = sha256_2_hex[:8]
        address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
        address_comp = base58(address_hex)

        ## WIF IT!
        digest = hashlib.sha256(binascii.unhexlify('80' + private)).hexdigest()
        var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
        var = binascii.unhexlify('80' + private + var[0:8])
        alphabet = chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        value = pad = 0
        result = ''
        for i, c in enumerate(var[::-1]):
            value += 256**i * c
        while value >= len(alphabet):
            div, mod = divmod(value, len(alphabet))
            result, value = chars[mod] + result, div
        result = chars[value] + result
        for c in var:
            if c == 0:
                pad += 1
            else:
                break
        wif = chars[0] * pad + result

        keys.append([private, wif, public, public_key_comp, address, address_comp])
    return keys


################################# COMPARE CODE #################################
def process(keys_list):
    keys_to_call = [];
    for i in keys_list:
        keys_to_call.append(i[3])
        keys_to_call.append(i[4])
    keys_ret = keys_to_call
    if keys_ret:
        with open('plutus.txt', 'a') as file:
            for i in keys_list:
                #if (i[3] == keys_ret[0] or i[4] == keys_ret[0]):
                #     file.write('hex private key: ' + str(i[0]) + '\n' +
                #      'WIF private key: ' + str(i[1]) + '\n' +
                #      'public key: ' + str(i[2]) + '\n' +
                #      'address uncomp: ' + str(i[3]) + '\n' +
                #      'address comped: ' + str(i[4]) + '\n\n')
                file.write(keys_ret)
                file.write(keys_list)
            print(keys_ret)
            print(keys_list)
        print(datetime.now().strftime("%m/%d/%Y, %H:%M:%S"))
        print('GOT ONE')


################################# THREAD CODE #################################
def main(sanity_1_s, sanity_2_s):
    max_sanity_check = int((100000/max_keys)-1)
    sanity_check = max_sanity_check+1
    #print('max sanity check: ' + str(max_sanity_check))
    while True:
        keys_t = keygen(max_keys)
        process(keys_t)
        if sanity_check > max_sanity_check:
            ret = False
            if ret:
                sanity_check = 0
            else:
                print('check failed:1')
                quit()
            ret = False
            if ret:
                sanity_check = 0
            else:
                print('check failed:2')
                quit()
        sanity_check = sanity_check + 1


################################# ENTRY, DATA LOAD, THREAD START #################################


keygen(32000)