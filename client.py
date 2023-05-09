#!/usr/bin/env python3.8
import socket,OpenSSL
from Crypto.Hash import SHA384
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import new
from base64 import b64encode,b64decode
from json import dumps,loads
import time
import pyotp
import qrcode
import os

def aes_get_msg_from_server(key, connection):
    json_input = connection.recv(1024)
    b64 = loads(json_input)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key.encode(),AES.MODE_CBC,iv=iv)
    pt = unpad(cipher.decrypt(ct),AES.block_size)
    return pt.decode()

def aes_send_msg_to_server(key, connection, msg):
    cipher = AES.new(key.encode(),AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(msg.encode(),AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = dumps({'iv':iv, 'ciphertext': ct})
    connection.send(result.encode())

def aes_authentication(key, connection):
    name_msg = aes_get_msg_from_server(key, connection)
    full_name = input(name_msg)
    aes_send_msg_to_server(key, connection, full_name)
    auth_msg = ""
    while auth_msg != "Authentication passed successfully!":
        if auth_msg != "auth_key":
            auth_msg = aes_get_msg_from_server(key, connection)
        if auth_msg == "auth_key":
            auth_key = input("Please enter your authentication key: ")
            aes_send_msg_to_server(key, connection, auth_key)
            auth_msg = aes_get_msg_from_server(key, connection)
        else: # auth_msg is URI (Uniform Resource Identifier)
            qrcode.make(auth_msg).save("qr_auth.png")
            print("Please use qr code from 'SecuredChat' directory for signing up")
            input("Press enter after scanning the qr code (WARNING: qr code will be deleted!)")
            os.remove("qr_auth.png")
    print(auth_msg)

def rsa_get_msg_from_server(RSAkey, connection):
    data = connection.recv(512)
    decrypted = PKCS1_OAEP.new(RSAkey,hashAlgo=SHA384).decrypt(data).decode()
    return decrypted

def rsa_send_msg_to_server(pub_key, connection, msg):
    cipher = PKCS1_OAEP.new(pub_key,hashAlgo=SHA384)
    ciphertext = cipher.encrypt(msg.encode())
    connection.send(ciphertext)

def rsa_authentication(RSAkey, pub_key, connection):
    name_msg = rsa_get_msg_from_server(RSAkey, connection)
    full_name = input(name_msg)
    rsa_send_msg_to_server(pub_key, connection, full_name)
    auth_msg = ""
    while auth_msg != "Authentication passed!":
        if auth_msg != "auth_key":
            auth_msg = rsa_get_msg_from_server(RSAkey, connection)
        if auth_msg == "auth_key":
            auth_key = input("Please enter your authentication key: ")
            rsa_send_msg_to_server(pub_key, connection, auth_key)
            auth_msg = rsa_get_msg_from_server(RSAkey, connection)
        else: # auth_msg is URI (Uniform Resource Identifier)
            qrcode.make(auth_msg).save("qr_auth.png")
            print("Please use qr code from 'SecuredChat' directory for signing up")
            input("Press enter after scanning the qr code (WARNING: qr code will be deleted!)")
            os.remove("qr_auth.png")
    print(auth_msg)

def clientServer():
    HOST = input("Server IP: ")
    PORT = int(input("Server Port: "))
    encryptionMode = int(input("(1) for AES (2) for RSA: "))
    if(encryptionMode == 2): # AES
        # Connection context\attributes and connecting to the server
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM, 0)
        connection = OpenSSL.SSL.Connection(context,s)
        connection.connect((HOST,PORT))
        # Keys generation and exchange
        RSAkey = RSA.generate(1024,new().read)
        RSApubkey = RSAkey.publickey()
        connection.send(RSApubkey.export_key(format = "PEM", passphrase = None, pkcs = 1))
        print("PubKey Sent")
        pub_key = RSA.import_key(connection.recv(1024), passphrase=None)
        print("PubKey received")
        rsa_authentication(RSAkey, pub_key, connection) # Client Authentication
        print("Send 'BYE' to exit the chat")
        while True: # chatting
            message = input("clientMessageTCP_RSA>>>: ")
            if(message == 'BYE'):
                rsa_send_msg_to_server(pub_key, connection, message)
                break
            rsa_send_msg_to_server(pub_key, connection, message)
            server_msg = rsa_get_msg_from_server(RSAkey, connection)
            if(server_msg == 'BYE'):
                break
            print("serverMessageTCP_RSA>>> " + server_msg)
        main()
    else:
        key = input('Please enter server AES key: ')
        # Connection context\attributes and connecting to the server
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM, 0)
        connection = OpenSSL.SSL.Connection(context,s)
        connection.connect((HOST,PORT))
        aes_authentication(key, connection) # Client Authentication
        print("Send 'BYE' to exit the chat")
        while True: # Chatting
            message = input("clientMessageTCP_AES>>>: ")
            if(message == 'BYE'):
                aes_send_msg_to_server(key, connection, message)
                break
            aes_send_msg_to_server(key, connection, message)
            server_msg = aes_get_msg_from_server(key, connection)
            if(server_msg == 'BYE'):
                break
            print("serverMessageTCP_AES>>>>>" + server_msg)
        main()

def main():
    clientServer()

if __name__ == "__main__":
    main()