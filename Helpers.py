import hashlib


def parse_multiaddr(maddr):
    maddr_info = maddr.split("/")
    assert len(maddr) == 6, f"incorrectly entered multi-address: {maddr_info}"
    ip_type, host_ip, protocol, port, _, signature = maddr_info
    assert ip_type == "ip4", f"incorrectly formated ip type: {ip_type}"
    assert protocol == "tcp", f"{protocol} is not supported"
    assert 0 < port < 2**16, f"{port} not in range 0 to {2**16}"

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

def verify_data_with_hash(data, hash):
    return hash_data(data) == hash

# First, establish TCP connection
# Second, send public IP