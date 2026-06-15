import socket 
import asyncio
import upnpclient
import argparse
import Helpers
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class Node:
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

    async def write(self, data:bytes):
        if self.writer != None:
            self.writer.write(Helpers.gen_header(data) + data)
            await self.writer.drain()
        else:
            raise Exception("Writer not initialized")

    async def read(self) -> bytes:
        if self.reader != None:
            header = await self.reader.read(4)
            length = Helpers.read_header(header)
            return await self.reader.read(length)
        else:
            raise Exception("Reader not initialized")
        
    async def end_connection(self, statement:str):
        print(statement)
        print("Connection closed")
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except ConnectionError:
            pass
        finally:
            return None
    
    async def handshake(self, is_server:bool = True) -> bytes | None:
        print("waiting on 1")
        # 1. Send peer ID for verification of connection
        if is_server == True:
            await self.write(self.peer_id)
        connection_peer_id = await self.read()
        if not connection_peer_id:
            return await self.end_connection("Peer did not send their peer id.")
        if is_server != True:
            await self.write(self.peer_id)

        print(connection_peer_id.hex())
        
        print("waiting on 2")
        # 2. Send actual public key for shared secret generation
        if is_server == True:
            await self.write(self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        
        # 2.5 Receive public key from connected peer
        pk_holder = await self.read()
        if not pk_holder:
            return await self.end_connection("Peer did not send their public key.")

        print("waiting on 3, 4, and 5")
        # 3. Serialize public key recieved and verify public key is correct
        connection_public_key = serialization.load_pem_public_key(pk_holder)
        if isinstance(connection_public_key, ec.EllipticCurvePublicKey):
            # 4. Confirm hash of public key equals to the previously sent peer id of the person connecting
            cpk_bytes = connection_public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
            cpk_hash = Helpers.crypto_hash(cpk_bytes)
            if cpk_hash != connection_peer_id:
                return await self.end_connection("Hash of peer public key isn't equal to peer id.")
  
            # 5. Shared secret exchange
            shared_secret = self.private_key.exchange(ec.ECDH(), connection_public_key)
        else:
            shared_secret = None
            return await self.end_connection("type of connection public key is not an ecpk")
        
        if is_server != True:
            await self.write(self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        
        print("waiting on 6")
        # 6. Salt for the session, server generates and sends to client 
        if is_server == True:
            session_salt = os.urandom(32)
            await self.write(session_salt)

            # 6.5 Accept confirmation of salt
            salt_confirmation = await self.read()
            if not salt_confirmation and salt_confirmation != b'Salt received':
                return await self.end_connection("Salt not recieved by peer.")
        else:
            session_salt = await self.read()
            if not session_salt:
                return await self.end_connection("session salt not sent")
            await self.write(b'Salt received')

        print("waiting on 7")
        # 7. Generate AES key to encrypt all messages
        AES_key = HKDF(algorithm = hashes.SHA256(), length = 32, salt = session_salt, info=b'handshake data').derive(shared_secret)
        return AES_key


    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader, self.writer = reader, writer
        addr = writer.get_extra_info('peername')
        print(f"Connection established with {addr}")
        AES_key = await self.handshake(is_server=True)
        print("handshake finished")
        '''while True:
            # Read data asynchronously
            data = await reader.read(1024)
            if not data:
                break  # Connection closed by client
                
            message = data.decode()
            print(f"Received: {message}")
            
            # Send a response back if needed
            writer.write(b"Data received successfully")
            await writer.drain()'''
        
        await self.end_connection("Connection closing")
        return

    async def start_node_as_server(self, port):
        try:
            self.node = await asyncio.start_server(self.handle_client, '127.0.0.1', port)
            addr = self.node.sockets[0].getsockname()
            print(f"Serving on {addr}")

            async with self.node:
                await self.node.serve_forever()
        finally:
            print("Server shutting down.")
            self.node.close()
            try:
                await self.node.wait_closed()
            except:
                pass
            print("Server closed.")
            return

    async def start_node_as_client(self, ip:str, port:int):
        try:
            self.reader, self.writer = await asyncio.open_connection(ip, port)
        except ConnectionRefusedError:
            print("Server is offline.")
            return
        
        try:
            AES_key = await self.handshake(is_server = False)
            print("handshake finished")
        except ConnectionError as e:
            print(f"Network error occurred: {e}")
        finally:
            return await self.end_connection("Connection closing")

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

async def create_node(port:int, destination:str):
    if port <= 0:
        port = 8000
    node = Node()
    if not destination:
        await node.start_node_as_server(port)
    else:
        maddr_info = Helpers.parse_multiaddr(destination)
        await node.start_node_as_client(maddr_info[1], int(maddr_info[3]))


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
        asyncio.run(create_node(args.port, args.destination))
        pass
    except KeyboardInterrupt:
        print("Program ending")
        pass
    pass

if __name__ == "__main__":
    main()