from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import socket 
import asyncio
import upnpclient
import argparse
import Helpers
import os
import sys
import re

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

    async def write(self, writer:asyncio.StreamWriter, data:bytes, AES_key:bytes | None = None)->None:
        try:
            if AES_key != None:
                payload = Helpers.payload_to_bytes(Helpers.encrypt_aes_256(data, AES_key))
            else:
                payload = data
            writer.write(Helpers.gen_header(payload) + payload)
            await writer.drain()
        except:
            pass

    async def read(self, reader:asyncio.StreamReader, AES_key:bytes|None = None) -> bytes:
        if reader != None:
            try:
                header = await reader.read(4)
            except:
                return b''
            if len(header) != 4:
                return b''
            length = Helpers.read_header(header)
            if length == 0:
                return b''
            if AES_key != None:
                return Helpers.decrypt_aes_256(Helpers.bytes_to_payload(await reader.read(length)), AES_key)
            else:
                return await reader.read(length)
        else:
            raise Exception("Reader not initialized")
        
    async def end_connection(self, writer: asyncio.StreamWriter, statement:str):
        print(statement)
        print("[INFO] Connection closed")
        #await self.write(writer, b"")
        writer.close()
        try:
            await writer.wait_closed()
            return None
        except ConnectionError:
            return None
        finally:
            return None
    
    async def handshake(self, reader:asyncio.StreamReader, writer:asyncio.StreamWriter, is_server:bool = True) -> bytes | None:
        # 1. Send peer ID for verification of connection
        if is_server == True:
            await self.write(writer, self.peer_id)
        connection_peer_id = await self.read(reader)
        if not connection_peer_id:
            return await self.end_connection(writer, "Peer did not send their peer id.")
        if is_server != True:
            await self.write(writer, self.peer_id)
        
        # 2. Send actual public key for shared secret generation
        if is_server == True:
            await self.write(writer, self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        
        # 2.5 Receive public key from connected peer
        pk_holder = await self.read(reader)
        if not pk_holder:
            return await self.end_connection(writer, "Peer did not send their public key.")

        # 3. Serialize public key recieved and verify public key is correct
        connection_public_key = serialization.load_pem_public_key(pk_holder)
        if isinstance(connection_public_key, ec.EllipticCurvePublicKey):
            # 4. Confirm hash of public key equals to the previously sent peer id of the person connecting
            cpk_bytes = connection_public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
            cpk_hash = Helpers.crypto_hash(cpk_bytes)
            if cpk_hash != connection_peer_id:
                return await self.end_connection(writer, "Hash of peer public key isn't equal to peer id.")
  
            # 5. Shared secret exchange
            shared_secret = self.private_key.exchange(ec.ECDH(), connection_public_key)
        else:
            shared_secret = None
            return await self.end_connection(writer, "Peer public key is not an ecpk")
        
        if is_server != True:
            await self.write(writer,self.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        
        # 6. Salt for the session, server generates and sends to client 
        if is_server == True:
            session_salt = os.urandom(32)
            await self.write(writer,session_salt)

            # 6.5 Accept confirmation of salt
            salt_confirmation = await self.read(reader)
            if not salt_confirmation and salt_confirmation != b'Salt received':
                return await self.end_connection(writer, "Salt not recieved by peer.")
        else:
            session_salt = await self.read(reader)
            if not session_salt:
                return await self.end_connection(writer, "Session salt not sent")
            await self.write(writer, b'Salt received')

        # 7. Generate AES key to encrypt all messages
        AES_key = HKDF(algorithm = hashes.SHA256(), length = 32, salt = session_salt, info=b'handshake data').derive(shared_secret)
        return AES_key

    async def listen_to_peer(self, reader:asyncio.StreamReader, AES_key):
        """Continuously reads incoming chat text from the server and prints it."""
        try:
            while True:
                payload = await self.read(reader, AES_key)
                data = payload.decode("utf-8")
                if not data or data == '' or data == '\n':
                    print("[DISCONNECTED] Connection closed by the peer.")
                    return
                    #break
                # Print the chat message received
                print(data, end='', flush=True)
        except asyncio.CancelledError:
            pass
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            print("[DISCONNECTED] Peer disconnected unexpectedly.")

    async def send_to_peer(self, writer:asyncio.StreamWriter, AES_key:bytes):
        """Reads input from local console stdin and ships it out to the server."""
        # Run the blocking loop in an executor so it doesn't freeze the async event loop
        loop = asyncio.get_running_loop()
        
        try:
            while True:
                # sys.stdin.readline() blocks, so we delegate it to a background thread
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line: # EOF / Ctrl+D
                    break
                    
                await self.write(writer, (f"[{self.username}]: " + line).encode("utf-8"), AES_key)
        except asyncio.CancelledError:
            return
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            print("[DISCONNECTED] Peer disconnected unexpectedly.")

    def prompt_for_username(self):
        self.username = input("Enter a username: ").strip()
        if len(self.username) > 20 or not re.match("^[a-zA-Z0-9 ]+$", self.username):
            raise ValueError("Security alert: Invalid input detected!")
        
    async def async_chat_function(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, AES_key):
        try:
            print("[CONNECTED] Established link to chat server.")
            # Run both listening and sending coroutines concurrently
            print(f"Welcome {self.username}")

            listener = asyncio.create_task(self.listen_to_peer(reader, AES_key))
            sender = asyncio.create_task(self.send_to_peer(writer, AES_key))

            done, pending = await asyncio.wait({listener, sender}, return_when=asyncio.FIRST_COMPLETED)

            for task in pending:
                task.cancel()

            await asyncio.gather(*pending, return_exceptions=True)
            
        except ConnectionRefusedError:
            print("[ERROR] Could not connect. Is the server running?")
        finally:
            print("[INFO] Client session ended.")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        #self.reader, self.writer = reader, writer
        addr = writer.get_extra_info('peername')
        print(f"[INFO] Connection established with {addr}")
        AES_key = await self.handshake(reader, writer, is_server=True)
        print("[INFO] Handshake finished")
        await self.async_chat_function(reader, writer, AES_key)
        await self.end_connection(writer, "Connection closing")
        return

    async def start_node_as_server(self, port):
        try:
            self.node = await asyncio.start_server(self.handle_client, '', port)
            print("\nValid multiaddresses:")
            for i in Helpers.get_valid_ip4_addrs():
                print(f"multi-address: ip4/{i}/tcp/{port}/p2p/{self.peer_id.hex()}")

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
            reader, writer = await asyncio.open_connection(ip, port)
        except ConnectionRefusedError:
            print("Server is offline.")
            return
        
        try:
            AES_key = await self.handshake(reader, writer, is_server = False)
            print("handshake finished")
            await self.async_chat_function(reader, writer, AES_key)
        except ConnectionError as e:
            print(f"Network error occurred: {e}")
        finally:
            await self.end_connection(writer, "Connection closing")
            return

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
    node.prompt_for_username()
    if not destination:
        await node.start_node_as_server(port)
    else:
        maddr_info = Helpers.parse_multiaddr(destination)
        await node.start_node_as_client(maddr_info[1], int(maddr_info[3]))
        return


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