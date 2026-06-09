import socket 
import asyncio
import upnpclient
import argparse
import Helpers
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

class Server:
    def __init__(self) -> None:
        # 1. Generate a private key using the SECP256R1 curve
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        # 2. Extract the corresponding public key
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        # 3. Sign a message
        self.peer_id = Helpers.crypto_hash(self.public_key_bytes)
        
    # 1. Send Peer ID between client and server
    # 2. Send public key between client and server
    # 3. Verify public key 
    # 4. Create shared secret

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        addr = writer.get_extra_info('peername')
        print(f"Connection established with {addr}")

        async def end_connection():
            print("Connection closed")
            writer.close()
            await writer.wait_closed() 

        writer.write(self.peer_id)
        await writer.drain()
        self.connection_peer_id = await reader.read(1024)
        if not self.connection_peer_id:
            await end_connection() # Connection closed by client
            return
        print(self.connection_peer_id)
        
        writer.write(self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        await writer.drain()
        self.connection_public_key = await reader.read(1024)
        if not self.connection_public_key:
            await end_connection() # Connection closed by client
            return
        print(self.connection_public_key)
        
        while True:
            # Read data asynchronously
            data = await reader.read(1024)
            if not data:
                break  # Connection closed by client
                
            message = data.decode()
            print(f"Received: {message}")
            
            # Send a response back if needed
            writer.write(b"Data received successfully")
            await writer.drain()
            
        await end_connection()

    async def start_node(self, port):
        self.node = await asyncio.start_server(self.handle_client, '0.0.0.0', port)
        addr = self.node.sockets[0].getsockname()
        print(f"Serving on {addr}")

        async with self.node:
            await self.node.serve_forever()

    async def recv_data(self):
        pass

    async def send_data(self):
        pass

    


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
        devices = upnpclient.discover()
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

def write_data():
    pass

def read_data():
    pass

def run(port, destination):
    pass

def main():
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
    parser.add_argument(
        "-p", 
        "--port", 
        default=0, 
        type=int, 
        help="source port number"
    )
    parser.add_argument(
        "-d",
        "--destination",
        type=str,
        help=f"destination multiaddr string, e.g. {example_maddr}",
    )
    args = parser.parse_args()

    try:
        #trio.run(run, *(args.port, args.destination))
        pass
    except KeyboardInterrupt:
        
        pass
    pass