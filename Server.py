import socket 
import asyncio
import upnpclient
import argparse
import Helpers
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Server:
    def __init__(self) -> None:
        # 1. Generate a private key using the SECP256R1 curve
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        # 2. Extract the corresponding public key
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
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

        async def write(data:bytes):
            self.writer.write(Helpers.gen_header(data) + data)
            await self.writer.drain()

        async def read() -> bytes:
            header = await reader.read(4)
            length = Helpers.read_header(header)
            return await reader.read(length)

        print("waiting on 1")
        # 1. Send peer ID for verification of connection
        await write(self.peer_id)
        # 1.5 Accept peer ID from connection
        self.connection_peer_id = await read()
        if not self.connection_peer_id:
            print("Peer did not send their peer id.")
            await end_connection()
            return
        print(self.connection_peer_id)
        
        print("waiting on 2")
        # 2. Send actual public key for shared secret generation
        await write(self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        
        # 2.5 Receive public key from connected peer
        temp_holder = await read()
        if not temp_holder:
            print("Peer did not send their public key.")
            await end_connection()
            return

        print("waiting on 3, 4, and 5")
        # 3. Serialize public key recieved and verify public key is correct
        print(self.connection_public_key)
        self.connection_public_key = serialization.load_pem_public_key(temp_holder)
        if isinstance(self.connection_public_key, ec.EllipticCurvePublicKey):
            # 4. Confirm hash of public key equals to the previously sent peer id of the person connecting
            cpk_bytes = self.connection_public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
            cpk_hash = Helpers.crypto_hash(cpk_bytes)
            if cpk_hash != self.peer_id:
                print("Hash of peer public key isn't equal to peer id.")
                await end_connection()
                return
            
            # 5. Shared secret exchange
            shared_secret = self.private_key.exchange(ec.ECDH(), self.connection_public_key)

        else:
            shared_secret = None
            raise TypeError
        
        print("waiting on 6")
        # 6. Salt for the session, server generates and sends to client 
        session_salt = os.urandom(32)
        await write(session_salt)

        # 6.5 Accept confirmation of salt
        salt_confirmation = await read()
        if not salt_confirmation and salt_confirmation != b'Salt received':
            print("Salt not recieved by peer.")
            await end_connection()
            return
        
        print("waiting on 7")
        # 7. Generate AES key to encrypt all messages
        AES_key = HKDF(algorithm = hashes.SHA256(), length = 32, salt = session_salt, info=b'handshake data').derive(shared_secret)
        

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