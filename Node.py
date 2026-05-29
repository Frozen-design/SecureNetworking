import secrets
import argparse
import logging
import sys
import trio
import multiaddr

# https://pypi.org/project/upnpclient/
import upnpclient

import socket

# https://py-libp2p.readthedocs.io
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
    find_free_port,
    get_available_interfaces,
    get_optimal_binding_address,
)
from libp2p.custom_types import (
    TProtocol,
)
from libp2p.abc import (
    INetStream,
)
from libp2p.peer.peerinfo import (
    info_from_p2p_addr,
)

logging.basicConfig(level=logging.WARNING)
logging.getLogger("multiaddr").setLevel(logging.WARNING)
logging.getLogger("libp2p").setLevel(logging.WARNING)

PROTOCOL_ID = TProtocol("/chat/1.0.0")
MAX_READ_LEN = 2**32 - 1

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

async def read_data(stream: INetStream) -> None:
    while True:
        read_bytes = await stream.read(MAX_READ_LEN)
        if read_bytes is not None:
            read_string = read_bytes.decode()
            if read_string != "\n":
                # Green console colour: 	\x1b[32m
                # Reset console colour: 	\x1b[0m
                print("\x1b[32m %s\x1b[0m" % read_string, end="")

async def write_data(stream: INetStream) -> None:
    async_f = trio.wrap_file(sys.stdin)
    while True:
        line = await async_f.readline()
        await stream.write(line.encode())

async def run(port: int, destination: str) -> None:
    if port <= 0:
        port = find_free_port()
        
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
    if not destination:
        host = new_host(key_pair=key_pair, sec_opt=security_options, enable_upnp=True)
    else:
        host = new_host(key_pair=key_pair, sec_opt=security_options)
    listen_addrs = get_available_interfaces(port)
    external_ip_addr = get_external_ip()
    listen_addrs.append(multiaddr.Multiaddr(f"/ip4/{external_ip_addr}/tcp/{port}"))
    #host = new_host()
    async with host.run(listen_addrs=listen_addrs), trio.open_nursery() as nursery:
        # Start the peer-store cleanup task
        nursery.start_soon(host.get_peerstore().start_cleanup_task, 60)

        if not destination:  # its the server

            async def stream_handler(stream: INetStream) -> None:
                nursery.start_soon(read_data, stream)
                nursery.start_soon(write_data, stream)

            host.set_stream_handler(PROTOCOL_ID, stream_handler)

            # Get all available addresses with peer ID
            all_addrs = host.get_addrs()

            print("Listener ready, listening on:\n")
            for addr in all_addrs:
                print(f"{addr}")

            print(f"public address:")
            public_multi_addr = f"/ip4/{external_ip_addr}/tcp/{port}"+ f"/p2p/{host.get_id().to_string()}"
            print(public_multi_addr)

            # Use optimal address for the client command
            optimal_addr = get_optimal_binding_address(port)
            optimal_addr_with_peer = f"{optimal_addr}"[1:] + f"/p2p/{host.get_id().to_string()}"
            print(
                f"\nRun this from the same folder in another console:\n\n"
                f"Lan: \npython Node.py -d {optimal_addr_with_peer}\n"
                f"UPnP: \npython Node.py -d {public_multi_addr[1:]}"
            )
            print("Waiting for incoming connection...")

        else:  # its the client
            maddr = multiaddr.Multiaddr(destination)
            info = info_from_p2p_addr(maddr)
            # Associate the peer with local ip address
            await host.connect(info)
            # Start a stream with the destination.
            # Multiaddress of the destination peer is fetched from the peerstore
            # using 'peerId'.
            stream = await host.new_stream(info.peer_id, [PROTOCOL_ID])

            nursery.start_soon(read_data, stream)
            nursery.start_soon(write_data, stream)
            print(f"Connected to peer {info.addrs[0]}")

        await trio.sleep_forever()

def main() -> None:
    description = """
    This program demonstrates a simple p2p chat application using libp2p.
    To use it, first run 'python ./chat -p <PORT>', where <PORT> is the port number.
    Then, run another host with 'python ./chat -p <ANOTHER_PORT> -d <DESTINATION>',
    where <DESTINATION> is the multiaddress of the previous listener host.
    """
    example_maddr = (
        "ip4/[HOST_IP]/tcp/8000/p2p/QmQn4SwGkDZKkUEpBRBvTmheQycxAHJUNmVEnjA2v1qe8Q"
    )
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-p", "--port", default=0, type=int, help="source port number")
    parser.add_argument(
        "-d",
        "--destination",
        type=str,
        help=f"destination multiaddr string, e.g. {example_maddr}",
    )
    args = parser.parse_args()

    try:
        trio.run(run, *(args.port, args.destination))
    except KeyboardInterrupt:

        pass

if __name__ == "__main__":
    main()