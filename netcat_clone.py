#! /usr/bin/env python

import sys
import socket
import getopt
import threading
import subprocess

listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0

# TODO/QUESTIONS:
#   Why did the tutorial writers decide to use 4096 and 1024 for the buffer size?
#   recv() documentations says this:
#      NOTE: For best match with hardware and network realities, the value of
#      bufsize should be a relatively small power of 2, for example, 4096.

# print's usage information to stdout before exiting
def usage():
    print "Simple Netcat Replacement"
    print
    print "Usage: netcat_clone.py -t target_host -p port"
    print "-l --listen                  listen on [host]:[port] for incoming connections"
    print "-e --execute=file_to_run     execute the given file upon receiving a connection"
    print "-c --command                 initialize a command shell"
    print "-u --upload=destination      upon receiving connection upload a file and write to [destination]"
    print
    print
    print "Examples: "
    print "netcat_clone.py -t 192.168.0.1 -p 5555 -l -c"
    print "netcat_clone.py -t 192.168.0.1 -p 5555 -l -u=/home/user/target.py"
    print "netcat_clone.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\""
    print "echo 'this is a message' | ./netcat_clone.py -t 192.168.11.12 -p 135"
    sys.exit(0)

def client_sender(var_buffer):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # connect to target host
        client.connect((target, port))
        if len(var_buffer):
            client.send(var_buffer)

        while True:
            # wait for response
            recv_len = 1
            response = ""

            while recv_len:
                data = client.recv(4096)
                recv_len = len(data)
                response+= data

                if recv_len < 4096:
                    break

            print response
            var_buffer = raw_input("")
            var_buffer += "\n"
            client.send(var_buffer)

    except:
        client.close()
        sys.exit("Exception. Exiting")

def server_loop():
    global target

    if not len(target):
        target = "0.0.0.0"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target, port))
    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        client_thread = threading.Thread(target=client_handler, args=(client_socket,))
        client_thread.start()

def run_command(command):
    command = command.rstrip()

    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except:
        output = "Failed to execute command \r\n"

    return output


def client_handler(client_socket):
    global upload
    global execute
    global command

    # This allows you to save to a file
    # This is how an attacker would download malware from remote locations
    if len(upload_destination):
        file_buffer = ""

        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            else:
                file_buffer += data

        try:
            file_descriptor = open(upload_destination, "wb")
            file_descriptor.write(file_buffer)
            file_descriptor.close()

            client_socket.send("Successfully save the file to %s\r\n" % upload_destination)
        except:
            client_socket.send("Failed to save the file to %s\r\n" % upload_destination)

    # Execute a single command
    if len(execute):
        output = run_command(execute)
        client_socket.send(output)

    # Opens an interactive shell
    if command:
        while True:
            client_socket.send("<netcat_clone:#> ")
            cmd_buffer = ""
            while "\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)

            response = run_command(cmd_buffer)
            client_socket.send(response)



# parses out options and arguments from argument suplied at execution
# and executes the rest of the program
def main():
    global listen
    global command
    global execute
    global target
    global upload_destination
    global port

    if not len(sys.argv[1:]):
        usage()

    ############################# Read Arguments #############################
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hle:t:p:cu:", ["help","listen","execute","target","port","command","upload"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for option,argument in opts:
        if option in ("-h", "--help"):
            usage()
        elif option in ("-l", "--listen"):
            listen = True
        elif option in ("-e", "--execute"):
            execute = argument
        elif option in ("-c", "--command"):
            command = True
        elif option in ("-u", "--upload"):
            upload_destination = argument
        elif option in ("-t", "--target"):
            target = argument
        elif option in ("-p", "--port"):
            # should catch exception for bad cast
            port = int(argument)
        else:
            assert False, "Unhandled Option"

    ######################### Execute With Options ##########################
    if not listen and len(target) and port > 0:
        stdin_buffer = sys.stdin.read()
        client_sender(stdin_buffer)

    if listen:
        server_loop()

main()



