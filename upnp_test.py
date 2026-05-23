import upnpclient
# https://pypi.org/project/upnpclient/
import socket

def example1():
    devices = upnpclient.discover()

    d = devices[0]
    print(devices)
    print(d)
    # get supported services: d.services
    print(d.services)
    # get actions of a service:
    # d["WANIPConn1].actions
    # d.WANIPConn1.actions
    print(d.WANIPConn1.actions)


def example2():
    msg = 'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMX:2\r\nMAN:"ssdp:discover"\r\n\r\n'.encode("utf-8")

    # Set up UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(2)
    s.sendto(msg, ('239.255.255.250', 1900) ) #type:ignore

    try:
        while True:
            data, addr = s.recvfrom(65507)
            print(addr, data.decode())
    except socket.timeout:
        pass

    msg = 'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:ssdp:all\r\nMX:2\r\nMAN:"ssdp:discover"\r\n\r\n'.encode("utf-8")

    # Set up UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(2)
    s.sendto(msg, ('239.255.255.250', 1900) ) #type:ignore

    try:
        while True:
            data, addr = s.recvfrom(65507)
            print(addr, data.decode())
    except socket.timeout:
        pass

example1()