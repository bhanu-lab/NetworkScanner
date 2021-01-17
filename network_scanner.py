import socket
import netifaces
import subprocess
import time
import threading
import re
import requests
import sys
import redis
import os
import logging

'''
Determine your own IP address
Determine your own netmask
Determine the network range
Scan all the addresses (except the lowest, which is your network address and the highest, which is your broadcast address).
Use your DNSs reverse lookup to determine the hostname for IP addresses which respond to your scan.
get mac addresses of available devices in network
get vendor name using mac address identified
'''

available_ips = []  # declaring available ips list
macs = {}  # declaring mac addresses map
host_prefix = ""
wanted_diff = []
device_types = {}  # map for ipaddress and device type
redis_db = redis.Redis(
    host=os.getenv('REDIS_HOST'),
    port=os.getenv('REDIS_PORT'),
    password=os.getenv('REDIS_PASS'))


# function to get local machine mac addr
def get_local_machine_mac_addr(local_ip):
    p = subprocess.Popen(["ip", "link"], stdout=subprocess.PIPE)
    data = p.communicate()[0]
    wlp2s0 = data.decode("utf-8").split("\n")[3]
    print(wlp2s0)
    macs[local_ip] = wlp2s0.strip().split(" ")[1]


# function to add mac address to macs map with key as ip address
def add_mac_addr(ip_addr, local_ip):
    if ip_addr != local_ip:
        pid = subprocess.Popen(["arp", "-n", ip_addr], stdout=subprocess.PIPE)
        data = pid.communicate()[0]

        # get mac address information from ipaddress using arp -n command on linux
        mac_addr = re.sub('\s+', ',', data.decode("utf-8").split("\n")[1])
        macs[mac_addr.split(",")[0]] = mac_addr.split(",")[2]
        # print(re.sub('\s+', ',', data.decode("utf-8").split("\n")[1]))


# function to check if an ip is live using ping function in unix
def check_ip_is_assigned(start, end, packets, local_ip, interface, host_prefix):

    for host in range(int(start), int(end)):
        ip_addr = host_prefix + str(host)
        device_types[local_ip] = "this device"
        if ip_addr != local_ip:
            # Ping -c for count of total number of packets to be sent
            #       -w for total number of milliseconds to be waiting
            ping = subprocess.Popen(['ping', '-c', str(packets), '-w', '1', '-i',
                                     '0.2', '-I', interface, ip_addr], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = ping.communicate()
            if ping.returncode == 0:
                logging.info("output of ping command is " + str(stdout))
                logging.info(ip_addr + " is available ")

                # identify device type and map against ip address
                device = device_identification_ping_response(stdout)
                device_types[ip_addr] = device

                available_ips.append(ip_addr)
                add_mac_addr(ip_addr, local_ip)

# function to identify device based on ping response


def device_identification_ping_response(device_response):
    device_type = "windows"
    if "ttl=64" in device_response.decode("UTF-8"):
        device_type = "*nix based device"

    return device_type


# function to check an assigned ip in LAN using arping
def check_ip_assigned_using_arping(start, end, packets, local_ip, interface, host_prefix):

    # arping -c 1 -f
    for host in range(int(start), int(end)):
        ip_addr = host_prefix + str(host)
        #       -f to return after 1 packet has sent to determine whether it is alive
        if ip_addr != local_ip:
            # Ping -c for count of total number of packets to be sent
            # print("number of packets "+packets)
            ping = subprocess.Popen(['arping', '-c', str(packets), '-f', '-I',
                                     interface, ip_addr], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = ping.communicate()
            if len(stderr) == 0 and len(stdout) > 0 and len(stdout.decode("utf-8").split("\n")[1].split(" ")) > 5:
                mac_addr = stdout.decode(
                    "utf-8").split("\n")[1].split(" ")[4][1:-1]
                if ping.returncode == 0:
                    print(ip_addr + " is available ")
                    available_ips.append(ip_addr)
                    # add_mac_addr(ip_addr)
                    macs[ip_addr] = mac_addr


# function to check if an ip is assigned using socket
def check_ip_is_live(start, end, local_ip):

    for host in range(int(start), int(end)):
        ip_addr = host_prefix + str(host)
        if ip_addr != local_ip:
            socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            try:
                # if connection successful socket connect returns 111
                result = socket_obj.connect_ex((ip_addr, 445))
                if result == 111:
                    available_ips.append(ip_addr)
                    add_mac_addr(ip_addr, local_ip)
            except:
                pass
            finally:
                socket_obj.close()


# function to get vendor name from mac address
def get_oui_from_mac_addr(mac_addr):
    print("Query to macvendor http://macvendors.co/api/"+mac_addr)
    mac_url = 'http://macvendors.co/api/%s'
    r = requests.get(mac_url % mac_addr)
    res = r.json()['result']
    if 'error' in res:
        return "unknown"
    elif 'company' in res:
        return res['company']
    else:
        return "unknown"

# function to return all available network interfaces


def get_network_interfaces():
    # obtaining all the network interfaces like eth, wlan
    interfaces = netifaces.interfaces()
    return interfaces


# function returns all the devices available on specific interface
def get_devices(intf):
    devices = []
    devices.clear()
    available_ips.clear()
    macs.clear()
    wanted_diff.append(intf)
    # noting start time
    start_time = time.time()

    # determine local machine ip address
    local_ip, s = get_local_ip()

    print("My local ip address is: " + local_ip +
          " and host name is: " + socket.gethostname())
    available_ips.append(local_ip)
    macs[local_ip] = "local host"
    get_local_machine_mac_addr(local_ip)
    s.close()

    # determine netmaskavailable_ips
    gateway = netifaces.gateways()

    # gateway for the network in which device is present
    default_gateway = gateway['default'][netifaces.AF_INET][0]
    print("default gateways is: " + str(default_gateway))

    packets = '5'
    # determine number of packets to be sent for querying if given in command line argument it will take from
    # command line else it will treat number of packets as 1
    if sys.argv[0] > '1':
        print("Only one or zero command line arguments are allowed ...")
    elif sys.argv[0] == '1':
        packets = sys.argv[1]

    scan_interface(default_gateway, local_ip, packets)

    # showing available IP's
    get_available_device_names(devices)

    # time taken for completing whole task
    duration = round(time.time() - start_time, 2)

    # calculating total time taken for the execution
    print(f"Total time taken is {duration} seconds")
    print(devices)
    return devices, duration

# add_nick_name_to_device adds nick name to device


def add_nick_name_to_device(ip, host_name, vendor):
    ans = input("Would You like to Store a Nick Name for this mac address ? Y/N")
    if ans == 'y':
        name = input("Enter Nick Name : ")
        redis_db.set(macs[ip], name)
        device = str(name.decode("utf-8") + " - " + ip +
                     " - " + host_name + " - "+"Vendor: "+vendor)
        return device

# with all available ips get mac addr and its vendor also try adding nick name to it


def get_available_device_names(devices):
    print("LIVE IP\'S AVAILABLE ARE: ")
    redis_db = redis.StrictRedis(host="localhost", port=6379, db=0)
    for ip in available_ips:
        # getfqdn will convert ip address into hostname
        host_name = ""
        try:
            host_name, aliases, ipaddrs = socket.gethostbyaddr(ip)
        except socket.herror:
            pass
        if ip in macs:
            mac_addr = macs[ip]
            nick_name = redis_db.get(mac_addr)
            vendor = get_oui_from_mac_addr(macs[ip])
            if host_name == '_gateway':
                print("setting gateway as device type router")
                device_types[ip] = "router"
            else:
                print("couldnt set router")
            print(ip + " - " + socket.getfqdn(ip) + " - mac addr : " +
                  macs[ip] + " - Vendor : " + vendor + " Device: " + str(nick_name))
            ''' use this for adding nick name to device
            if nick_name is None:
                device = add_nick_name_to_device(ip, host_name, vendor)
                devices.append(device)'''
            if nick_name is None:
                nick_name = b'Test_Device'

            device = str(nick_name.decode("utf-8") +
                         " - " + ip + " - " + host_name + " - "+"Vendor: "+vendor+" - mac addr : " + macs[ip] + " - DeviceType: " + device_types[ip])
            devices.append(device)
        else:
            device = ip + "-" + "unknown mac " + host_name
            devices.append(device)


# scan interface for knowing all devices alive on network
def scan_interface(default_gateway, local_ip, packets):
    # obtaining all the network interfaces like eth, wlan
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        if interface in wanted_diff:
            print("Scanning network: " + str(interface) + "\n")
            addrs = netifaces.ifaddresses(str(interface))
            try:
                print(addrs[netifaces.AF_INET])
            except KeyError:
                print("No address assigned for interface : " + interface)

            addrs = default_gateway.split('.')
            # print("last device number of subnetwork : {}" + str(int(addrs[3])+1))
            host_prefix = addrs[0] + "." + addrs[1] + "." + addrs[2] + "."
            print("host prefix is " + host_prefix)
            start_addr = 1
            end_addr = 26
            threads = []

            print(
                "\nPlease wait while I am scanning network ... It takes approx 30 sec ...\n")

            for i in range(0, 10):  # making number of threads to 10 to ping asynchronously

                # making sure ip address scanning wont exceed 255
                if end_addr < 255:
                    # creating multiple threads to complete the scan quickly
                    t = threading.Thread(target=check_ip_is_assigned,
                                         args=(start_addr, end_addr, packets, local_ip, interface, host_prefix))
                    start_addr = start_addr + 25
                    end_addr = end_addr + 25
                    t.start()
                    threads.append(t)

            # joining all the threads
            for t in threads:
                t.join()


# returns local ip address
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    print("SOCK Details : " + str(s.getsockname()))
    local_ip = s.getsockname()[0]
    return local_ip, s


# add nick name for mac address
def add_nick_name_for_device(mac_tobe_updated, name):
    redis_db.set(mac_tobe_updated, name)
    return True


# get all keys available in db
def get_all_names():
    all_values = {}
    keys = redis_db.keys("*")
    # print(keys)
    for key in keys:
        all_values[key.decode("utf-8")] = redis_db.get(key).decode("utf-8")
    return all_values
