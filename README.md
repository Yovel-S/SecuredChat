
## Secured 2FA chat infrastructure.
## May be used as an infrastructure for server-client or p2pa pplication

# Prerequisites:

### install these libraries:

    * pyopenssl

    * pycryptodome

    * pyotp

    * qrcode

### Server folder should contain the file clients.json which is the clients-qr_key dictionary.

### For running you must provide certificate and private key for TLS in the same folder of server code named 'certificate.crt' and 'privateKey.key'.

### Create certificate and private key with the command:
"openssl req -new -newkey rsa:4096 -x509 -sha384 -days 365 -nodes -out certificate.crt -keyout privateKey.key"

### Client must have a device with "Google Authenticator" app for the Two-Factor Authentication.

# Running the chat:
    1. ./server.py
    2. choose port for listening
    3. choose encryption mode
    4. ./client.py
    5. insert server ip
    6. insert server listening port
    7. choose encryption mode (same as server)
    8. authenticate yourself as a client using the "Google Authenticator" app
    9. start chatting!




