#!/usr/bin/env python3.8
import socket,OpenSSL
from Crypto.Hash import SHA384
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import new
from Crypto.Util.Padding import unpad,pad
from base64 import b64decode,b64encode
import json
from json import loads,dumps
import time
import pyotp
import qrcode

def generate_qr_code(clients, client_name):
    qr_key = pyotp.random_base32()
    clients[client_name] = qr_key
    uri = pyotp.totp.TOTP(qr_key).provisioning_uri(name=client_name,issuer_name='SecuredChat')
    return uri

def aes_get_msg_from_client(key, conn):
    json_input = conn.recv(1024)
    b64 = loads(json_input)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key.encode(),AES.MODE_CBC,iv=iv)
    pt = unpad(cipher.decrypt(ct),AES.block_size)
    return pt.decode()

def aes_send_msg_to_client(key, conn, msg):
    cipher = AES.new(key.encode(),AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(msg.encode(),AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = dumps({'iv':iv, 'ciphertext': ct})
    conn.send(result.encode())

def aes_authenticate_client(key, conn):
    auth_passed_successfully = False
    with open('clients.json', 'r') as clients_file:
        clients = json.load(clients_file)
    message = "Please enter your full name: "
    aes_send_msg_to_client(key, conn, message)
    client_name = aes_get_msg_from_client(key, conn)
    while not auth_passed_successfully:
        if client_name in clients:
            message = "auth_key"
            aes_send_msg_to_client(key, conn, message)
            client_auth_key = aes_get_msg_from_client(key, conn)
            totp = pyotp.TOTP(clients[client_name])
            auth_passed_successfully = totp.verify(client_auth_key)
        else:
            uri = generate_qr_code(clients, client_name)
            with open('clients.json', 'w') as clients_file:
                json.dump(clients, clients_file)
            aes_send_msg_to_client(key, conn, uri)
    aes_send_msg_to_client(key, conn, "Authentication passed successfully!")

def rsa_send_msg_to_client(pub_key, conn, msg):
    cipher = PKCS1_OAEP.new(pub_key,hashAlgo=SHA384)
    ciphertext = cipher.encrypt(msg.encode())
    conn.send(ciphertext)

def rsa_get_msg_from_client(RSAkey, conn):
    data = conn.recv(512)
    decrypted = PKCS1_OAEP.new(RSAkey,hashAlgo=SHA384).decrypt(data).decode()
    return decrypted

def rsa_authenticate_client(RSAkey, pub_key, conn):
    auth_passed_successfully = False
    with open('clients.json', 'r') as clients_file:
        clients = json.load(clients_file)
    message = "Please enter your full name: "
    rsa_send_msg_to_client(pub_key, conn, message)
    client_name = rsa_get_msg_from_client(RSAkey, conn)
    while not auth_passed_successfully:
        if client_name in clients:
            message = "auth_key"
            rsa_send_msg_to_client(pub_key, conn, message)
            client_auth_key = rsa_get_msg_from_client(RSAkey, conn)
            totp = pyotp.TOTP(clients[client_name])
            auth_passed_successfully = totp.verify(client_auth_key)
        else:
            uri = generate_qr_code(clients, client_name) # URI is (Uniform Resource Identifier), for unique qr code generation
            with open('clients.json', 'w') as clients_file:
                json.dump(clients, clients_file)
            rsa_send_msg_to_client(pub_key, conn, uri)
    rsa_send_msg_to_client(pub_key, conn, "Authentication passed!")

def listenServer():
    HOST = socket.gethostbyname(socket.gethostname())
    PORT = int(input("Server port: "))
    print("Server ip:" + HOST + "\nPort:" + str(PORT))
    encryptionMode = int(input("(1) for AES (2) for RSA: "))
    if(encryptionMode == 2): # RSA
        # Connection context\attributes
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
        context.use_certificate_file('certificate.crt')
        context.use_privatekey_file('privateKey.key')
        # Create socket and waiting for connection
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM, 0)
        connection = OpenSSL.SSL.Connection(context,s)
        connection.bind((HOST, PORT))
        connection.listen(2)
        print("Waiting for connections...")
        conn, addr = connection.accept()
        print("Client: "+ str(addr[0]) + " connected")
        # Keys generation and exchange
        RSAkey = RSA.generate(1024,new().read)
        RSApubkey = RSAkey.publickey()
        conn.send(RSApubkey.export_key(format = "PEM", passphrase = None, pkcs = 1))
        print("Public key sent to client")
        pub_key = RSA.import_key(conn.recv(1024), passphrase=None)
        print("Public key received")
        rsa_authenticate_client(RSAkey, pub_key, conn) # client authentication
        print("Send 'BYE' to exit the chat")
        while True: # Chatting
            client_msg = rsa_get_msg_from_client(RSAkey, conn)
            if(client_msg == 'BYE'):
                break
            print("clientMessageTCP_RSA>>> " + client_msg)
            message = input("serverMessageTCP_RSA>>>")
            if(message == 'BYE'):
                rsa_send_msg_to_client(pub_key, conn, message)
                break
            rsa_send_msg_to_client(pub_key, conn, message)
        main()
    else: # AES
        # Connection context\attributes
        key = input("Please enter valid AES key (16 bytes):")
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
        context.use_certificate_file('certificate.crt')
        context.use_privatekey_file('privateKey.key')
        # Create socket and waiting for connection
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM, 0)
        connection = OpenSSL.SSL.Connection(context,s)
        connection.bind((HOST, PORT))
        connection.listen(2)
        print("Waiting for connections...")
        conn, addr = connection.accept()
        print("Client: "+ str(addr[0]) + " connected")
        aes_authenticate_client(key, conn) # client authentication
        print("Client: "+ str(addr[0]) + " has been authenticated")
        print("Send 'BYE' to exit the chat")
        while True: # Chatting
            client_msg = aes_get_msg_from_client(key, conn)
            if(client_msg == 'BYE'):
                break
            print("clientMessageTCP_AES>>>>>" + client_msg)
            message = input("serverMessageTCP_AES>>>")
            if(message == 'BYE'):
                aes_send_msg_to_client(key, conn, message)
                break
            aes_send_msg_to_client(key, conn, message)
        main()

def main():
    listenServer()

if __name__ == "__main__":
    main()