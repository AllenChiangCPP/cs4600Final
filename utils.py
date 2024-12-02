from cryptography.hazmat.primitives import serialization
import base64

#function for reading RSA key from PEM file to use in another file
def load_key(filename, is_private=False):
    #open pem file as rb, and read the pem file data and deserializeds content of file and return it
    with open(filename, 'rb') as f:
        key_data = f.read()
        if is_private:
            return serialization.load_pem_private_key(key_data, password=None)
        else:
            return serialization.load_pem_public_key(key_data)

#function for saving encrypted data and MAC authentication code (MAC) to Transmitted_Data file
def save_transmitted_data(encrypted_aes_key, iv, encrypted_message, mac):
    #Open Transmitted_Data file and write encrypted ases key, intialization vector for AES encryption, the encrypted message, and the MAC
    #generated for the encrypted message
    with open("Transmitted_Data", "wb") as f:
        f.write(base64.b64encode(encrypted_aes_key) + b"\n")
        f.write(base64.b64encode(iv) + b"\n")
        f.write(base64.b64encode(encrypted_message) + b"\n")
        f.write(base64.b64encode(mac))

#funciton for reading transmitted data and extracting encrypted components
def load_transmitted_data():
    #open Transmitted_Data file and extract encrypted AES key, AES initialization vector, encrypted message, and MAC
    with open("Transmitted_Data", "rb") as f:
        lines = f.readlines()
        encrypted_aes_key = base64.b64decode(lines[0].strip())
        iv = base64.b64decode(lines[1].strip())
        encrypted_message = base64.b64decode(lines[2].strip())
        mac = base64.b64decode(lines[3].strip())
    return encrypted_aes_key, iv, encrypted_message, mac
