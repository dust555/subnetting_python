from ipaddress import IPv4Network
from ipaddress import IPv4Address
from ipaddress import IPv4Interface
import ipaddress
import random
import struct
import math
import os

#windows
clear = lambda: os.system('cls')
#linux and mac
#clear = lambda: os.system('clear')

from dataclasses import dataclass

@dataclass
class IPInfo:
    ip: IPv4Address
    CIDR: int
    subnet: IPv4Address
    network: IPv4Address
    broadcast: IPv4Address
    firsthost: IPv4Address
    lasthost: IPv4Address
    hosts: float
    allhosts: list


def random_ip(network):
    network = IPv4Network(network)
    network_int, = struct.unpack("!I", network.network_address.packed)
    rand_bits = network.max_prefixlen - network.prefixlen
    rand_host_int = random.randint(0, 2**rand_bits - 1)
    ip_address = IPv4Address(network_int + rand_host_int)
    return ip_address.exploded

def print_network_information(ipv4network: IPv4Network) -> None:
    """Prints the network address, broadcast address and number
    of addresses on the given IPv4 network.
    """

    print('Subnet Mask:', ipv4network.netmask)
    print('Network address:', ipv4network.network_address)
    print('Broadcast address:', ipv4network.broadcast_address)
    print('Number of hosts:', ipv4network.num_addresses)

    hosts = list(ipv4network.hosts())
    print('Fist host address:', hosts[0])
    print('Last host address:', hosts[-1])

def generate_network_info(ipv4address: IPv4Interface):
    ipv4network = IPv4Network(ipv4address.network)
    hosts = list(ipv4network.hosts())
    # info = IPInfo(ipv4address.ip, ipv4network.prefixlen, ipv4network.netmask, ipv4network.network_address, ipv4network.broadcast_address, hosts[0], hosts[-1], ipv4network.num_addresses-2)
    info = IPInfo(ipv4address.ip, ipv4network.prefixlen, ipv4network.netmask, ipv4network.network_address, ipv4network.broadcast_address, hosts[0], hosts[-1], ipv4network.num_addresses, hosts)
    return info

def generate_random_interface(netfrom=14, netto=30):
    ip = random_ip("0.0.0.0/0")
    netmask = str(random.randint(netfrom, netto))
    interface = IPv4Interface(ip+"/"+netmask)
    return interface



def ex_subnetmask(dir: int):
    info = generate_network_info(generate_random_interface())
    if dir == 0:
        print("CIDR: " + str(info.CIDR))
        print("Dotted Decimal notation:")
    else:
        print("CIDR: ")
        print("Dotted Decimal notation:" + str(info.subnet))

    input("Press Enter for solution")
    clear()
    print("CIDR: " + str(info.CIDR))
    print("Dotted Decimal notation:" + str(info.subnet))
    input("Press Enter for new")

def ip2bin(ip):
    ip =  ".".join(map(str,["{0:08b}".format(int(x)) for x in str(ip).split(".")]))
    return ip

def ip2binsubnet(ip, cidr):
    ip = ip2bin(ip)
    place = cidr + math.floor(cidr/8)
    return ip[0:place] + "|" + ip[place:len(ip)]
    



def ex_hosts() -> None:
    info = generate_network_info(generate_random_interface())
    sub = random.randint(0, 1)
    if sub == 0:
        print("IP: " + str(info.network) + "/" + str(info.CIDR))
        print("Subnet mask: ")
    else:
        print("IP: " + str(info.network) + "/..")
        print("Subnet mask: " + str(info.subnet))
    
    print("IP in binary: ")

    print("Number of network bits: ")
    print("Number of host bits: ")
    print("Number of available host addresses: ")

    input("Press Enter for solution")
    clear()

    print("IP: " + str(info.network) + "/" + str(info.CIDR))
    print("Subnet mask: " + str(info.subnet))

    print("IP in binary (network | host): " + ip2binsubnet(info.network,info.CIDR))
    
    print("Number of network bits: " + str(info.CIDR))
    print("Number of host bits: " + str(32 - int(info.CIDR)))
    print("Number of available host addresses: " + str(info.hosts-2))
    
    
    input("Press Enter for new")


def ex_ip_net_broad_host() -> None:
    info = generate_network_info(generate_random_interface())
    sub = random.randint(0, 1)
    if sub == 0:
        print("IP: " + str(info.ip) + "/" + str(info.CIDR))
        print("Subnet mask: ")
    else:
        print("IP: " + str(info.ip) + "/..")
        print("Subnet mask: " + str(info.subnet))
    
    print("Network address: ")
    print("Broadcast address: ")
    print("First available host address: ")
    print("Last available host address: ")
    print("Number of available host addresses: ")

    input("Press Enter for solution")
    clear()

    print("IP: " + str(info.ip) + "/" + str(info.CIDR))
    print("Subnet mask: " + str(info.subnet))
    
    print("Network address: " + str(info.network) + " \t\t\t--> (All host bits set to 0: " + ip2binsubnet(info.network,info.CIDR) + ")")
    print("Broadcast address: " + str(info.broadcast) + " \t\t--> (All host bits set to 1: " + ip2binsubnet(info.broadcast,info.CIDR) + ")")
    print("First available host address: " + str(info.firsthost) + " \t--> (Network address +1: " + ip2binsubnet(info.firsthost,info.CIDR) + ")")
    print("Last available host address: " + str(info.lasthost) + " \t--> (Broadcast address -1: " + ip2binsubnet(info.lasthost,info.CIDR) + ")")
    print("Number of available host addresses: " + str(info.hosts-2))
    
    
    input("Press Enter for new")

def ex_subnet_networks() -> None:
    networks = random.randint(2,8)
    netbits = math.ceil(math.log2(networks))
    info = generate_network_info(generate_random_interface(14,30-(netbits)))
    print("Starting network address: " + str(info.network) + "/" + str(info.CIDR))
    print("Number of needed networks: " + str(networks))
    input("Press Enter for solution")
    clear()

    print("Starting network address: " + str(info.network) + "/" + str(info.CIDR))
    print("Number of needed networks: " + str(networks))

    netbits = math.ceil(math.log2(networks))
    totalnetworks = int(math.pow(2,netbits))
    print("Number of additional network bits: " + str(netbits))
    print("Total number of networks: " + str(totalnetworks))
    print("Number of unused networks: " + str(totalnetworks - networks))

    subnet_network_networks(info,networks)

    input("Press Enter for new")

def ex_subnet_hosts() -> None:
    hosts = random.randint(2,1024)
    hostbits = math.ceil(math.log2(hosts + 2))
    info = generate_network_info(generate_random_interface(30-(hostbits+1),30-(hostbits)))
    print("Starting network address: " + str(info.network) + "/" + str(info.CIDR))
    print("Maximum number of hosts on a network: " + str(hosts))
    input("Press Enter for solution")
    clear()

    networks = math.pow(2,(32 - info.CIDR - hostbits))
    print("Starting network address: " + str(info.network) + "/" + str(info.CIDR))
    print("Maximum number of hosts on a network: " + str(hosts))

    netbits = math.ceil(math.log2(networks))
    totalnetworks = int(math.pow(2,netbits))
    print("Number of needed host bits: " + str(hostbits))
    print("Total number of networks: " + str(totalnetworks))
    subnet_network_networks(info,networks)

    input("Press Enter for new")

def subnet_network_networks(network: IPInfo, networks: int):
    netbits = math.ceil(math.log2(networks))
    totalnetworks = int(math.pow(2,netbits))
    netmask = str(int(network.CIDR) + netbits)
    print("New subnet mask: /" + netmask)

    for i in range(int(totalnetworks)):
        print("---------------------------------------")
        print("Network " + str(i+1))
        networkplace = int(i * (len(network.allhosts)+2)/totalnetworks)
        interface = IPv4Interface(str(network.allhosts[networkplace])+"/"+netmask)
        info = generate_network_info(interface)
        print("Network Address: " + str(info.network) + "/" + str(info.CIDR))
        print("Fist Host Address: " + str(info.firsthost))
        print("Last Host Address: " + str(info.lasthost))
        print("Broadcast Address: " + str(info.broadcast))
        print("Number of hosts: " + str(info.hosts-2))

def subnet_network_hosts(network: IPInfo, hosts: int):
    hostbits = math.ceil(math.log2(hosts))
    totalnetworks = int(math.pow(2,netbits))
    print("Number of additional network bits: " + str(netbits))
    print("Total number of networks: " + str(totalnetworks))
    print("Number of unused networks: " + str(totalnetworks - networks))
    netmask = str(int(network.CIDR) + netbits)
    print("New subnet mask: /" + netmask)

    for i in range(int(totalnetworks)):
        print("---------------------------------------")
        print("Network " + str(i+1))
        networkplace = int(i * (len(network.allhosts)+2)/totalnetworks)
        interface = IPv4Interface(str(network.allhosts[networkplace])+"/"+netmask)
        info = generate_network_info(interface)
        print("Network Address: " + str(info.network) + "/" + str(info.CIDR))
        print("Fist Host Address: " + str(info.firsthost))
        print("Last Host Address: " + str(info.lasthost))
        print("Broadcast Address: " + str(info.broadcast))
        print("Number of hosts: " + str(info.hosts-2))


def main() -> None:
    ex = 1
    while ex > 0:
        clear()
        print("1: Subnet, CIDR to dotted decimal")
        print("2: Subnet, dotted decimal to CIDR")
        print("3: Hosts in a network")
        print("4: Network, broadcast first and last host")
        print("5: Subnet network based on number of needed networks")
        print("6: Subnet network based on maximum number of needed hosts")
        print("0: Exit")

        ex = int(input("Choose your exersise:"))

        clear()

        if ex == 1:
            ex_subnetmask(0)
        elif ex == 2:
            ex_subnetmask(1)
        elif ex == 3:
            ex_hosts()
        elif ex == 4:
            ex_ip_net_broad_host()
        elif ex == 5:
            ex_subnet_networks()
        elif ex == 6:
            ex_subnet_hosts()



if __name__ == '__main__':
    main()
