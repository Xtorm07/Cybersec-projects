#!/usr/bin/env python3
#This is a project of an alternative to nmap or any other network scanner
#A lightweight and of easy use network scanner that can be run with python
import socket
import errno
import threading 
from sys import argv, exit
import getopt
import ipaddress
from datetime import datetime

open_ports = 0
lock = threading.Lock()

verbosity = False
target = ""
first_port = 0
last_port = 0
write_file = False
file_path = ""
concurrent_thr = 200


def banner():
    global target
    global date
    date =  datetime.now()
    start_time = date.strftime("%Y/%m/%d %H:%M:%S")
    print(r"$$$$$$$\                      $$\              $$\                                                        ")      
    print(r"$$  __$$\                     $$ |           $$$$$$\                                                       ")     
    print(r'$$ |  $$ | $$$$$$\   $$$$$$\$$$$$$\         $$  __$$\  $$$$$$$\$$$$$$\  $$$$$$$\  $$$$$$$\   $$$$$$\   $$$$$$\ ')
    print(r"$$$$$$$  |$$  __$$\ $$  __$$\_$$  _|        $$ /  \__|$$  _____\____$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ ") 
    print(r"$$  ____/ $$ /  $$ |$$ |  \__|$$ |          \$$$$$$\  $$ /     $$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|")
    print(r"$$ |      $$ |  $$ |$$ |      $$ |$$\        \___ $$\ $$ |    $$  __$$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |      ")
    print(r"$$ |      \$$$$$$  |$$ |      \$$$$  |      $$\  \$$ |\$$$$$$$\$$$$$$$ |$$ |  $$ |$$ |  $$ |\$$$$$$$\ $$ |      ")
    print(r"\__|       \______/ \__|       \____/       \$$$$$$  | \_______\_______|\__|  \__|\__|  \__| \_______|\__|      ")
    print(r"                                             \_$$  _/                                                           ")
    print(r"                                               \ _/                                                           ")
    print("\u203E" * 106)  
    print(f"Target IP Adress {target}")
    print(f"Scan Started at {start_time}")                                                                                     
    print("\u203E" * 106)  


def usage():
    print("Port Scanner, A Lightweight Scrapper")
    print("Usage: python port-scanner.py -t target_host -p port -v")
    print("-t --target                  -Select a target for the scan (e.g. 10.10.0.1)")
    print("                               Or a network address with its submask to scan the network")
    print("                               e.g. 192.168.0.128/25                                   ")
    print("-p --port                    -Scan a port or port range using a '-' between port-ranges"
          )
    print("-v --verbosity               -For verbosity mode and see every other port even if is closed")
    print("-o --output                  -To output the results to a file, specifying the file path")
    print("-c --concurrent              -Defines the amount of concurrent threads to use at the same time")
    print("                               from 50 to 500 default is 200")
    print("Examples: ")
    print("python port-scanner.py -t 192.168.0.1 -p 5555 ")
    print("python port-scanner.py -t 192.168.100.1 -p 100-800 -o /file/to/path")
    print("python port-scanner.py -t 192.168.100.0/24 -p 1-1024 -c 350 ")
    exit(0)

def write_to_file(data):
    global file_path
    with open(file_path, "a") as file:
        file.write(data + "\n")

def scan_port(port, address):
    global open_ports
    global verbosity
    global write_file
    output = ""
    try:
        #Making the socket connection and sending packets to the target
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3) #waiting for response
            result = sock.connect_ex((address, port)) #The response given by the port        
        #If port is open it will give back a 0 response
        if result == 0:
            try:
                #Getting the service of the port using the local service file
                service = socket.getservbyport(port)
            except:
                service = "Service Not Known"
            #Accesing the variable with lock to not harm the content of the ports by the threads
            with lock:
                #Adding open port with a locking
                open_ports += 1
            output = f'[*] port {port} is \033[34mopen \033[0m-> {service}' #The \033 is for displaying the output with colors
            print(output) #Printing the open port and its service

        #If its closed it will give this response
        elif verbosity and result == errno.ECONNREFUSED: #Checking if the connection was refused
            output = f"[*] Port {port} is \033[31mclosed \033[0m"
            print(output)

        #If its filtered it will give this response
        elif result in (errno.EHOSTUNREACH, errno.ETIMEDOUT): #Checking if the response timed out to evaluate if it was filtered
            try:
                service = socket.getservbyport(port)
            except:
                service = "Service Not Known"
            output = f"[*] port {port} is \033[33mfiltered \033[0m-> {service}" 
            print(output) 
        if write_file and output != "":
            with lock:
                write_to_file(output)
    #Keyboard interruption if ctrl + C was pressed
    except KeyboardInterrupt:
        print(f"\nScript Interrupted by user. Exiting...")

    #Exception in case occurs an error
    except socket.error:
        print(f"Target {address} not responding")
    except Exception as e:
        print(f"Ocurred an error while scanning the port: {e}")


def range_ports(address, start_port, final_port):
    global open_ports
    global write_file
    global concurrent_thr
    banner()
    thread_list = [] #Creating a thread list
    output = ""
    network_addr = ipaddress.ip_network(address, strict=False)
    try:
        for device in network_addr.hosts(): 
            #making a thread to each port in the range
            for port in range(start_port, final_port + 1):
                thread = threading.Thread(target=scan_port, args=(port, str(device)))
                thread_list.append(thread)
                thread.start()
                #Limiting the amount of threads to make it smoother and not make too much noise
                if len(thread_list) >= concurrent_thr:
                    for thr in thread_list:
                        thr.join()
                    thread_list = []
            
            for threads in thread_list:
                threads.join()
            thread_list = []

            if open_ports == 0:
                #Check if there were no open ports in all devices
                print(f"No Open ports on {device}")
            else:
                print(f"Total Open ports in {device} are [{open_ports}]")
                open_ports = 0
            if write_file and output != "":
                   write_to_file(output)
    except KeyboardInterrupt:
        print(f"\nScript Interrupted by user. Exiting...")


def options():
    global first_port
    global last_port
    global target
    global verbosity
    global write_file
    global file_path
    global concurrent_thr

    try:
        opts, args = getopt.getopt(argv[1:], "ht:p:vc:o:", 
                                    ["help","target=", "port=", "verbosity","concurrent=", "output="])
    except getopt.GetoptError as err:
        print("\n--" + str(err) + "--\n")
        usage()
        exit(1)

    if not len(argv[1:]):
        usage()


    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            exit(0)
        elif opt in ("-t", "target="):
            target = arg
        elif opt in ("-p" or "--port="):
            if arg.count("-") == 1:
                first_port, last_port = map(int, arg.split("-"))
            else:
                first_port = int(arg)
                last_port = int(arg)
        elif opt in ("-v" or "--verbosity"):
            verbosity = True
        elif opt in ("-o" or "--output"):
            write_file = True
            file_path = arg
        elif opt in ("-c" or "--concurrent") and 50 <= int(arg) <= 500:
            concurrent_thr = int(arg) 
        else:
            assert False, "Unhandled Option"
    
    if target == "":
        print("--No target selected--\n")
        usage()
    elif first_port == 0 and last_port == 0:
        print("--No port selected--\n")
        usage()
    
    range_ports(target, first_port, last_port)

if __name__ == "__main__":
    options()
