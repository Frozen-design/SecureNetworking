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

example1()