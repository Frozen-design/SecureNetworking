import secrets

import trio

# https://pypi.org/project/upnpclient/
import upnpclient

import socket

from libp2p import (
    new_host,
)
from libp2p.crypto.secp256k1 import (
    create_new_key_pair,
)
from libp2p.crypto.x25519 import create_new_key_pair as create_new_x25519_key_pair
from libp2p.security.noise.transport import (
    PROTOCOL_ID as NOISE_PROTOCOL_ID,
    Transport as NoiseTransport,
)
from libp2p.utils.address_validation import (
    get_available_interfaces,
    get_optimal_binding_address,
)

class Server:
    def __init__(self) -> None:
        pass

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def get_external_ip():
    try:
        gw_addr = upnpclient.discover()[0].WANIPConn1.GetExternalIPAddress()['NewExternalIPAddress']
    except:
        return None
    return gw_addr

def port_forward(external_port:int, internal_port:int, open_close:str, duration = 60):
    IP = get_local_ip()
    devices = upnpclient.discover()
    d = devices[0]
    try:
        d.WANIPConn1.AddPortMapping(
            NewRemoteHost = '0.0.0.0',
            NewExternalPort=external_port,
            NewProtocol='TCP',
            NewInternalPort=internal_port,
            NewInternalClient=IP,
            NewEnabled=open_close,
            NewPortMappingDescription='Client-server testing',
            NewLeaseDuration=duration
        )
    except:
        print("port mapping already exists")

async def main():
    # Create a key pair for the host
    secret = secrets.token_bytes(32)
    key_pair = create_new_key_pair(secret)
    noise_key_pair = create_new_x25519_key_pair()

    # Create a Noise security transport
    noise_transport = NoiseTransport(
        # libp2p_keypair: libp2p identity (distinct from the Noise static key per spec)
        libp2p_keypair=key_pair,
        # noise_privkey: X25519 static key for Noise DH (libp2p Noise spec)
        noise_privkey=noise_key_pair.private_key,
        # early_data: Optional data to send during the handshake
        # (None means no early data)
        early_data=None,
    )

    # Create a security options dictionary mapping protocol ID to transport
    security_options = {NOISE_PROTOCOL_ID: noise_transport}

    #bootstrap_nodes = ["/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"]

    # Create a host with the key pair, Noise security, and mplex multiplexer
    host = new_host(key_pair=key_pair, sec_opt=security_options, enable_upnp=True)

    # Configure the listening address using the new paradigm
    port = 7900
    """port_forward(port, port, '0')
    public_addr = f"/ip4/{get_external_ip()}/tcp/{port}/p2p/{host.get_id().to_base58()}"
    print("Public addr:", public_addr)"""
    listen_addrs = get_available_interfaces(port)
    optimal_addr = get_optimal_binding_address(port)

    # Start the host
    async with host.run(listen_addrs=listen_addrs):
        print("libp2p has started")
        print("libp2p is listening on:", host.get_addrs())
        print(f"Optimal address: {optimal_addr}")
        # Keep the host running
        await trio.sleep_forever()


# Run the async function
trio.run(main)