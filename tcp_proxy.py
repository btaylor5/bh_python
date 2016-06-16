#! /usr/bin/env python

import sys
import socket
import threading
import string

def server_loop(local_host,local_port,remote_host,remote_port,receive_first):

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((local_host, local_port))
    except:
        print "[!!!] Failed to listen on %s:%d" % (local_host, local_port)
        print "[!!!] Check for other listening sockets and/or correct permissions"

    print "[ * ] Listening on %s:%d" % (local_host, local_port)
    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        print "[==>] Receiving incoming connection from %s:%d" % (addr[0], addr[1])

        # start thread to talk to the  remote host proxy_thread
        proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))

        proxy_thread.start()

def proxy_handler(client_socket, remote_host, remote_port, receive_first):

    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    if receive_first:
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

        # send it to our response handler
        remote_buffer = response_handler(remote_buffer)

        # if there is data, send it to local client
        if len(remote_buffer):
            print "[<==] Sending %d bytes to localhost." % len(remote_buffer)
            client_socket.send(remote_buffer)

        while True:
            local_buffer = receive_from(client_socket)

            if len(local_buffer):
                print "[==>] Received %d bytes from localhost." % len(local_buffer)

                # send it to the request handler
                local_buffer = request_handler(local_buffer, replace_localhost, "127.0.0.1", remote_host)
                hexdump(local_buffer)


                remote_socket.send(local_buffer)
                print "[==>] Sent to remote"

            # receive the response
            remote_buffer = receive_from(remote_socket)

            if len(remote_buffer):
                print "[==>] Received %d bytes from remote." % len(remote_buffer)
                hexdump(remote_buffer)

                # send it to the request handler
                remote_buffer = response_handler(remote_buffer)

                client_socket.send(remote_buffer)
                print "[==>] Sent to localhost"

            if not len(local_buffer) or not len(remote_buffer):
                client_socket.close()
                remote_socket.close()
                print "[ * ] No More Data. Connections Closed."
                break

def hexdump(src, length=16):
    results = []
    digits = 4 if isinstance(src, unicode) else 2
    for i in xrange(0, len(src), length):
        s = src[i:i+length]
        hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        results.append( b"%04X %-*s %s" % (i, length*(digits + 1), hexa, text))
    print b'\n'.join(results)

def receive_from(connection, timeout=2):
    var_buffer = ""

    connection.settimeout(timeout)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            var_buffer += data
    except:
        pass

    return var_buffer

# Rewrote these two function to be more modular.
# Now I can write many functions and choose which ones are called instead of
# constantly rewriting/hacking on these functions
def request_handler(buffer, function=None, *args):
    if function is not None:
        buffer = function(buffer, *args)
    return buffer

def response_handler(buffer, function=None, *args):
    if function is not None:
        buffer = function(buffer, *args)
    return buffer

def replace_localhost(buffer, targeted, replacement):
    buffer = string.replace(buffer, targeted, replacement)
    return buffer

def main():
    # no fancy command-line parsing here
    if len(sys.argv[1:]) != 5:
        print "Usage: ./proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]"
        print "Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True"
        sys.exit(0)

    local_host = sys.argv[1]
    local_port = int(sys.argv[2])
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    # connect and receive data before sending to the remote host
    receive_first = sys.argv[5]
    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False

    # spin up a socket for listening
    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

main()
