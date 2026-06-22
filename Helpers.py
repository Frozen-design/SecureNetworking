from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json
import struct
import socket 
import ifaddr
import ipaddress
import upnpclient

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except Exception:
        print("PC not connected to a network")
        return "127.0.0.1"
    finally:
        s.close()
    return IP

def get_external_ip():
    try:
        gw_addr = upnpclient.discover()[0].WANIPConn1.GetExternalIPAddress()['NewExternalIPAddress']
    except:
        return None
    return gw_addr

def port_forward(external_port:int, internal_port:int, open_close:bool = True, duration = 60):
    open_close_str = "1" if open_close else "0"
    IP = get_local_ip()
    if IP == "127.0.0.1":
        raise Exception("Cannot port forward on a PC not connected to the internet")
    try:
        devices:list[upnpclient.upnp.Device] = upnpclient.discover()
        d = devices[0]
    except IndexError:
        print("No devices on the network to port forward")
        raise
    try:
        d.WANIPConn1.AddPortMapping(
            NewRemoteHost = '0.0.0.0',
            NewExternalPort=external_port,
            NewProtocol='TCP',
            NewInternalPort=internal_port,
            NewInternalClient=IP,
            NewEnabled=open_close_str,
            NewPortMappingDescription='Client-server testing',
            NewLeaseDuration=duration
        )
    except:
        print("port mapping already exists")

def get_valid_ip4_addrs():
    adapters = ifaddr.get_adapters()
    ipv4_addrs = []
    for adapter in adapters:
        for i in adapter.ips:
            if i.is_IPv4 and not ipaddress.ip_address(str(i.ip)).is_link_local:
                ipv4_addrs.append(str(i.ip))
    return ipv4_addrs

def parse_multiaddr(maddr):
    maddr_info = maddr.split("/")
    #assert len(maddr) == 6, f"incorrectly entered multi-address: {maddr_info}"
    ip_type, host_ip, protocol, port, _, signature = maddr_info
    assert ip_type == "ip4", f"incorrectly formated ip type: {ip_type}"
    assert protocol == "tcp", f"{protocol} is not supported"
    assert 0 < int(port) < 2**16, f"{port} not in range 0 to {2**16}"
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

def encrypt_aes_256(plaintext:bytes, AES_key:bytes) -> dict:
    iv = os.urandom(12)
    encyptor = Cipher(algorithms.AES256(AES_key), modes.GCM(iv)).encryptor()
    ciphertext = encyptor.update(plaintext) + encyptor.finalize()
    tag = encyptor.tag
    payload_dict = {
        "ciphertext": ciphertext,
        "iv": iv,
        "tag": tag
        }
    return payload_dict

def payload_to_bytes(payload_dict:dict) -> bytes:
    payload_hex = {
        "ciphertext": payload_dict["ciphertext"].hex(),
        "iv": payload_dict["iv"].hex(),
        "tag": payload_dict["tag"].hex()
        }
    return json.dumps(payload_hex).encode("utf-8")

def decrypt_aes_256(data:dict, AES_key:bytes) -> bytes:
    decryptor = Cipher(
        algorithms.AES256(AES_key),
        modes.GCM(data["iv"], data["tag"])
    ).decryptor()
    
    decrypted_text = decryptor.update(data["ciphertext"]) + decryptor.finalize()
    return decrypted_text

def bytes_to_payload(data:bytes) -> dict:
    payload = json.loads(data.decode("utf-8"))
    payload_dict = {
        "ciphertext": bytes.fromhex(payload["ciphertext"]),
        "iv": bytes.fromhex(payload["iv"]),
        "tag": bytes.fromhex(payload["tag"])
        }
    return payload_dict
