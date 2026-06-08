
"""class Client:
    def __init__(self, ip_p, ip, protocol, port) -> None:
        self.ip_protocol = ip_p
        self.ip = ip
        self.protocol = protocol
        self.port = port
        # 1. Generate a private key using the SECP256R1 curve
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        # 2. Extract the corresponding public key
        self.public_key = self.private_key.public_key()
        # 3. Sign a message
        self.peer_id = self.private_key.sign(f"{self.public_key}".encode(), ec.ECDSA(hashes.SHA256()))
        pass"""