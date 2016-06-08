#! /usr/bin/env python
import socket

target_host = "127.0.0.1"
target_port = 9999

# AF_INET is IPv4 address or hostname
# SOCK_STREAM means TCP client
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((target_host, target_port))
client.send("GET / HTTP/1.1\r\nHost: Test!\r\n\r\n")
response = client.recv(4096)
print response
