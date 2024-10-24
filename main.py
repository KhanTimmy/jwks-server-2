from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import time

hostName = "localhost"
serverPort = 8080

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def get_public_key(private_key):
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    return {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": "goodKID",
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e),
    }
def jwks_response():
    key_pem = fetch_key(expired=False)
    if key_pem is None:
        return {}
        
    private_key = serialization.load_pem_private_key(
        key_pem.encode('utf-8'),
        password=None
        )

    public_key_data = get_public_key(private_key)
    return {
        "keys": [
            public_key_data
            ]
        }


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        try:
            parsed_path = urlparse(self.path)
            params = parse_qs(parsed_path.query)  # This returns a dictionary, not a set

            # Check if the 'expired' parameter is present
            expired_param = params.get('expired', ['false'])[0].lower() == 'true'

            # Fetch the appropriate key based on whether the "expired" parameter is present
            key_pem = fetch_key(expired=expired_param)

            if key_pem is None:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"No valid key available")
                return

            # Load the PEM private key
            private_key = serialization.load_pem_private_key(
                key_pem.encode('utf-8'),
                password=None
        )

            headers = {"kid": "goodKID"}
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }

            if expired_param:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

            encoded_jwt = jwt.encode(token_payload, private_key, algorithm='RS256', headers=headers)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))

        except Exception as e:
            print(f"Error processing request: {e}")
            self.send_response(500)
            self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            jwks = jwks_response()  # Fetch the valid JWKS response
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

    # Function to connect to the SQLite database
def connect_to_database():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    return conn

    # Create the keys table if it doesn't exist
def setup_database():
    conn = connect_to_database()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys(
                 kid INTEGER PRIMARY KEY AUTOINCREMENT,
                     key BLOB NOT NULL,
                     exp INTEGER NOT NULL
                )''')
    conn.commit()
    conn.close()
        # Insert a new key into the database
    # Insert a new key into the database
def save_key_to_db(key, exp):
    conn = connect_to_database()
    c = conn.cursor()
    # Corrected: changed 'key_pem' to 'key' to match the table schema
    c.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key, exp))
    conn.commit()
    conn.close()

# Fetch a valid or expired key from the database
def fetch_key(expired=False):
    conn = connect_to_database()
    current_time = int(time.time())
    if expired:
        query = 'SELECT key FROM keys WHERE exp <= ? LIMIT 1'  # Correct column 'key'
        result = conn.execute(query, (current_time,)).fetchone()
    else:
        query = 'SELECT key FROM keys WHERE exp > ? LIMIT 1'  # Correct column 'key'
        result = conn.execute(query, (current_time,)).fetchone()
    conn.close()
    if result:
        return result[0]
    return None

def insert_keys():
    #Insert a valid key (expires in 1 hour)
    valid_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    expiration_time = int(time.time()) + 3600 # 1 hour in the future
    save_key_to_db(valid_key_pem, expiration_time)

    #Insert an expired key (expires in 1 hour)
    expired_key_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    expiration_time = int(time.time()) - 3600 # 1 hour in the past
    save_key_to_db(expired_key_pem, expiration_time)



if __name__ == "__main__":
    setup_database()
    insert_keys()
    webServer = HTTPServer((hostName, serverPort), MyServer)

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
