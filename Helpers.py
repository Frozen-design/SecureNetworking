from cryptography.hazmat.primitives import hashes

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

# First, establish TCP connection
# Second, send public IP