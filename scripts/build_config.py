from base64 import b64encode, b64decode
from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import uuid
import hashlib

def formatChar(string_to_convert):
    format1 = "-".join(string_to_convert[i:i+2] for i in range(0, len(string_to_convert), 2))
    format2 = "-{}".format(format1)
    format3 = format2.replace("-", " 0x").replace(" ", ", ").replace(",","",1)
    return format3

def calculate_key_iv():
    random_string_uuid = uuid.uuid4()
    random_string_iv = uuid.uuid4()
    md5_string_key = hashlib.md5(str(random_string_uuid).encode('utf8')).hexdigest()
    md5_iv_string = hashlib.md5(str(md5_string_key).encode('utf8')).hexdigest()
    
    print("[+] Raw AES Key: " + md5_string_key)
    print("[+] Raw IV: " + md5_iv_string)
    
    return md5_string_key, md5_iv_string, random_string_uuid

def build_config():

    # enter the IP:PORT config to be encrypted
    input_config_data = "127.0.0.1:9999"

    # print original config data
    print("Original Config: ", input_config_data)
    print("\n" + "-" * 75 + "\n")

    original_password, original_iv, random_string_uuid = calculate_key_iv()
    print("Raw UUID string: {}\n".format(random_string_uuid))


    # perform the encryption
    iv = unhexlify(original_iv)
    password = unhexlify(original_password)

    input_config_data = pad(input_config_data.encode(), AES.block_size)
    cipher = AES.new(password, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(input_config_data)

    # print the C++ ready code
    print("// AES IV - Hex formatted random IV")
    print("const unsigned char iv[16] = {{{} }};".format(formatChar(original_iv)))
    print("// AES Key - MD5 hash of a random UUID string")
    print("const std::vector<unsigned char> key = {{{} }};".format(formatChar(original_password)))
    print("// AES Ciphertext - Encrypted configuration data")
    print("std::vector<unsigned char> encrypted_config = {{{} }};".format(formatChar(cipher_text.hex())))

    print("\n" + "-" * 75 + "\n")

    # check if the decryption works
    out = b64encode(cipher_text).decode('utf-8')
    decipher = AES.new(password, AES.MODE_CBC, iv)
    plaintext = unpad(decipher.decrypt(b64decode(out)), AES.block_size).decode('utf-8')
    print("Decryption attempt: ", plaintext)

if __name__ == '__main__':
    build_config()
