import asyncio
from localtunnel.tunnel_manager import TunnelManager

class Server:
    def __init__(self) -> None:
        pass

async def main():
    manager = TunnelManager()
    manager.add_tunnel(port = 7900, subdomain="test")

    try:
        await manager.open_all()
        for tunnel in manager.tunnels:
            print(f"Tunnel open at URL: {tunnel.get_tunnel_url()}")

        # Keep running
        await asyncio.Event().wait()
    finally:
        await manager.close_all()
    pass

if __name__ == "__main__":
    asyncio.run(main())