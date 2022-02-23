import base64
import argparse
import hashlib
import sys
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from secrets import token_bytes
from Cryptodome.Random import get_random_bytes
from cryptography.fernet import Fernet

parser = argparse.ArgumentParser()
parser.add_argument("-m", "--mode", help="Mention encode or decode")
parser.add_argument("-t", "--text", help="Enter the plain text/encoded data to encode/decode")
args = parser.parse_args()

def aes_encrypt(password, text):
            salt = get_random_bytes(AES.block_size)
            private_key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
            cipher_config = AES.new(private_key, AES.MODE_GCM)
            cipher_text, tag = cipher_config.encrypt_and_digest(bytes(text, 'utf-8'))
            return {
                'cipher_text': base64.b64encode(cipher_text).decode('utf-8'),
                'salt': base64.b64encode(salt).decode('utf-8'),
                'nonce': base64.b64encode(cipher_config.nonce).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8')
            }

def aes_decrypt(dict, password):
    salt = base64.b64decode(dict['salt'])
    cipher_text = base64.b64decode(dict['cipher_text'])
    nonce = base64.b64decode(dict['nonce'])
    tag = base64.b64decode(dict['tag'])
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)
    return decrypted

def DES_encrypt(key, text):
    cipher = DES.new(key, DES.MODE_EAX)
    nonce = cipher.nonce
    cipher_text, tag = cipher.encrypt_and_digest(text.encode("ascii"))
    return nonce, cipher_text, tag

def DES_decrypt(key, nonce, cipher_text, tag):
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    plain_text = cipher.decrypt(cipher_text)
    try:
        cipher.verify(tag)
        return plain_text.decode("ascii")
    except:
        return False

if args.mode.lower() == "encode":
    if not args.text:
        print("Enter the text to encode")
        sys.exit(0)
    print("Enter the algorithm in which the data is to be encoded")
    print("For printing available algorithms, enter 99")
    option = str(input("Type here --> "))
    if option == "99":
        print("AES")
        print("Single DES")
        print("Fernet")
        print("base64")
        print("base32")
        print("Rot13")
        print("Fernet Symmetric Encryption")
        option = str(input("Type here --> "))

    #For Base64
    if option.lower() == "base64":
        print("You selected to encode in Base64 format")
        string_bytes = args.text.encode("ascii")
        base64_bytes = base64.b64encode(string_bytes)
        base64_data = base64_bytes.decode("ascii")
        print("The encoded data is: {}".format(base64_data))
    #For Base32
    if option.lower() == "base32":
        print("You selected to encode in Base32 format")
        string_bytes = args.text.encode("ascii")
        base32_bytes = base64.b32encode(string_bytes)
        base32_data = base32_bytes.decode("ascii")
        print("The encoded data is: {}".format(base32_data))
    
    #For Rot13
    if option.lower() == "rot13":
        print("You selected to encode in Rot13 format")
        rot13 = str.maketrans('ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz','NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm')
        rot13_encoded = str.translate(args.text, rot13)
        print("The encoded data is: {}".format(rot13_encoded))
    
    #For AES
    if option.lower() == "aes":
        password = str(input("Enter a password. Remember that this password is used for decryption also."))
        text =args.text
        enc = aes_encrypt(password, text)
        print(enc)
        yn = str(input("Do you want to decrypt the same again?? (Y/N)"))
        if yn.upper() == "Y":
            print(aes_decrypt(enc, password))
        elif yn.upper() == "N":
            print("Ok then....Thanks for using.... Bye")
            sys.exit(0)
        else:
            print("Enter only Y or N")
            sys.exit(0)
    
    #For Single DES
    if option.lower() == "single des":
        key = token_bytes(8)
        text = args.text
        nonce, cipher_text, tag = DES_encrypt(key, text)
        print("Cipher text: {}".format(cipher_text))
        print("Key used: {}".format(key))
        print("Nonce: {}".format(nonce))
        print("Tag: {}".format(tag))
        yn2 = str(input("Do you want to decrypt the same again?? (Y/N)"))
        if yn2.upper() == "Y":
            print(DES_decrypt(key, nonce, cipher_text, tag))
        elif yn2.upper() == "N":
            print("Ok then....Thanks for using.... Bye")
            sys.exit(0)
        else:
            print("Enter only Y or N")
            sys.exit(0)
        
    #For Fernet
    if option.lower() == "fernet":
        print("You selected to encode using fernet")
        fernet_key = Fernet.generate_key()
        f = Fernet(fernet_key)
        print("Key: {}".format(fernet_key))
        fernet_bytes = args.text.encode()
        encoded_fernet = f.encrypt(fernet_bytes)
        print("The encoded data is: {}".format(encoded_fernet))
        
if args.mode.lower() == "decode":
    if not args.text:
        print("Enter the text to decode.")
    print("Enter the algorithm in which the data is to be encoded")
    print("For printing available algorithms, enter 99")
    option = str(input("Type here --> "))
    if option == "99":
        print("AES")
        print("Single DES")
        print("base64")
        print("base32")
        print("Rot13")
        print("Fernet Symmetric Encryption")
        option = str(input("Type here --> "))
    #For Base64
    if option.lower() == "base64":
        print("You selected to decode in Base64 format")
        base64_decoded = base64.b64decode(args.text)
        print("The decoded data is: {}".format(base64_decoded))
    
    #For Base32
    if option.lower() == "base32":
        print("You selected to decode in Base32 format")
        base32_decoded = base64.b32decode(string_bytes)
        print("The decoded data is: {}".format(base32_decoded))
    
    #For Rot13
    if option.lower() == "rot13":
        print("You selected to encode in Rot13 format")
        rot13 = str.maketrans('ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz','NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm')
        rot13_encoded = str.translate(args.text, rot13)
        print("The encoded data is: {}".format(rot13_encoded))
    
    #For AES
    if option.lower() == "aes":
        password = str(input("Enter a password used.: "))
        salt2 = str(input("Enter the salt: "))
        cipher_text2 = args.text
        nonce2 = str(input("Enter nonce: "))
        tag2 = str(input("Enter the tag: "))
        new_dict = {}
        new_dict['salt'] = salt2
        new_dict['cipher_text'] = cipher_text2
        new_dict['nonce'] = nonce2
        new_dict['tag'] = tag2
        print(aes_decrypt(new_dict, password))

    #For Single DES
    if option.lower() == "single des":
        des_dict = {}
        key3 = input("Enter the key: ").encode().decode('unicode_escape').encode("raw_unicode_escape")
        nonce3 = input("Enter nonce: ").encode().decode('unicode_escape').encode("raw_unicode_escape")
        cipher_text3 = args.text.encode().decode('unicode_escape').encode("raw_unicode_escape")
        tag3 = input("Enter the tag: ").encode().decode('unicode_escape').encode("raw_unicode_escape")
        print(DES_decrypt(key3, nonce3, cipher_text3, tag3))
    
    if option.lower() == "fernet":
        print("You selected to decode using fernet")
        decode_key = input("Enter the key: ").encode()
        print(decode_key)
        f = Fernet(decode_key)
        fernet_bytes = args.text.encode()
        decoded_fernet = f.decrypt(fernet_bytes)
        print("The encoded data is: {}".format(decoded_fernet.decode()))
