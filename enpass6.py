#!/usr/bin/env python3

import os
import binascii
import hashlib
import hmac
from pathlib import Path
from pysqlcipher3 import dbapi2 as sqlite
from Crypto.Cipher import AES

# Sources:
#   - https://www.enpass.io/docs/security-whitepaper-enpass/vault.html
#   - https://discussion.enpass.io/index.php?/topic/4446-enpass-6-encryption-details/
#   - https://www.zetetic.net/sqlcipher/sqlcipher-api/
PBKDF2_ROUNDS = 100000
ENPASS_DB = os.environ["ENPASS_DB"]
KEY_FILE = os.environ["ENPASS_KEY_FILE"]  # can be 'export ENPASS_KEY_FILE=""'
PASSWORD = os.environ["ENPASS_PASSWORD"]


def make_digest(message, key):
    message = bytes(message, 'UTF-8')
    digester = hmac.new(key, message, hashlib.sha1)
    signature = digester.hexdigest()
    return signature


def make_master_password(password: bytes, key_path: Path):
    if not key_path:
        return password

    key_hex_xml = Path(key_path).read_bytes()
    # no need to use XML lib for such a simple string operation
    cut_key_value = slice(5, -6)
    key_hex = key_hex_xml[cut_key_value]
    key_bytes = binascii.unhexlify(key_hex)
    return password + key_bytes


def main():
    master_password = make_master_password(PASSWORD, KEY_FILE)

    # The first 16 bytes of the database file are used as salt
    enpass_db_salt = open(ENPASS_DB, "rb").read(16)

    # The database key is derived from the master password
    # and the database salt with 100k iterations of PBKDF2-HMAC-SHA512
    enpass_db_key = hashlib.pbkdf2_hmac(
        "sha512", master_password, enpass_db_salt, PBKDF2_ROUNDS
    )

    # The raw key for the sqlcipher database is given
    # by the first 64 characters of the hex-encoded key
    enpass_db_hex_key = enpass_db_key.hex()[:64]
    enpass_mac_hex_key = enpass_db_key.hex()[64:]

    conn = sqlite.connect(ENPASS_DB)

    c = conn.cursor()
    c.row_factory = sqlite.Row
    c.execute(f"PRAGMA key=\"x'{enpass_db_hex_key}'\";")
    c.execute("PRAGMA cipher_compatibility = 3;")

    c.execute("SELECT i.title, i.uuid, i.key, if.value, if.hash FROM item i, itemfield if WHERE if.type = \"password\" AND i.uuid = if.item_uuid;")
    for row in c:
        # The key object is saved in binary from and actually consists of the
        # AES key (32 bytes) and a nonce (12 bytes) for GCM
        key = row["key"][:32]
        nonce = row["key"][32:]
        # If you deleted an item from Enpass, it stays in the database, but the
        # entries are cleared
        if not nonce:
            continue

        # The value object holds the ciphertext (same length as plaintext) +
        # (authentication) tag (16 bytes) and is stored in hex
        length = len(row["value"])
        ciphertext = bytearray.fromhex(row["value"][:length - 32])
        tag = bytearray.fromhex(row["value"][length - 32:])

        # As additional authenticated data (AAD) they use the UUID but without
        # the dashes: e.g. a2ec30c0aeed41f7aed7cc50e69ff506
        uuid = row["uuid"]
        header = uuid.replace("-", "")

        # Now we can initialize, decrypt the ciphertext and verify the AAD.
        # You can compare the SHA-1 output with the value stored in the db
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(bytearray.fromhex(header))
        password = cipher.decrypt(ciphertext)
        try:
            cipher.verify(tag)
            h = hashlib.new('sha1')
            h.update(password)
            print(row["title"] + ":\t" + "SHA-1(\"" + password.decode("utf-8") + "\")\t= " + h.hexdigest())
        except ValueError:
            print("Key incorrect or message corrupted")

if __name__ == "__main__":
    main()
