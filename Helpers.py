from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json
import struct


def parse_multiaddr(maddr):
    maddr_info = maddr.split("/")
    assert len(maddr) == 6, f"incorrectly entered multi-address: {maddr_info}"
    ip_type, host_ip, protocol, port, _, signature = maddr_info
    assert ip_type == "ip4", f"incorrectly formated ip type: {ip_type}"
    assert protocol == "tcp", f"{protocol} is not supported"
    assert 0 < port < 2**16, f"{port} not in range 0 to {2**16}"
    return maddr_info

def crypto_hash(data:bytes):
    digest_ctx = hashes.Hash(hashes.SHA256())
    digest_ctx.update(data)
    raw_bytes_digest = digest_ctx.finalize()
    return raw_bytes_digest

def gen_header(data:bytes) -> bytes:
    header = struct.pack('>I', len(data))
    return header

def read_header(header:bytes) -> int:
    length = struct.unpack('>I', header)[0]
    return length

def encrypt_aes_256(plaintext:str, AES_key:bytes) -> dict:
    iv = os.urandom(12)
    encyptor = Cipher(algorithms.AES256(AES_key), modes.GCM(iv)).encryptor()
    ciphertext = encyptor.update(plaintext.encode()) + encyptor.finalize()
    tag = encyptor.tag
    payload_dict = {
        "ciphertext": ciphertext,
        "iv": iv,
        "tag": tag
        }
    return payload_dict

def payload_to_bytes(payload_dict:dict):
    payload_hex = {
        "ciphertext": payload_dict["ciphertext"].hex(),
        "iv": payload_dict["iv"].hex(),
        "tag": payload_dict["tag"].hex()
        }
    return json.dumps(payload_hex).encode("utf-8")

def decrypt_aes_256(data:dict, AES_key:bytes) -> str:
    decryptor = Cipher(
        algorithms.AES256(AES_key),
        modes.GCM(data["iv"], data["tag"])
    ).decryptor()
    
    decrypted_text = decryptor.update(data["ciphertext"]) + decryptor.finalize()
    return decrypted_text.decode()

def bytes_to_payload(data:bytes) -> dict:
    payload = json.loads(data.decode("utf-8"))
    payload_dict = {
        "ciphertext": bytes.fromhex(payload["ciphertext"]),
        "iv": bytes.fromhex(payload["iv"]),
        "tag": bytes.fromhex(payload["tag"])
        }
    return payload_dict
