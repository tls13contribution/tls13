from bs4 import BeautifulSoup
import sys
import os
import subprocess
import json
import urllib.request
import time
import signal
import struct
import socket

address = {}
organizations = {}

def usage():
    print ("Resolve unknowns of the IP address")
    print ("python3 unknown.py <input file name> <output file name> <address file> <organization file>")
    exit(1)

def check_valid(addr):
    addr_lst = addr.split(".")
    dot_count = len(addr_lst) - 1

    if dot_count < 3:
        while dot_count < 3:
            addr_lst.append('0')
            dot_count = dot_count + 1

    if addr_lst[-1] == '0':
        addr_lst[-1] = '1'
        addr = ".".join(addr_lst)
    return addr

def add_hosts(ip, number):
    host_bit = 32 - number
    hosts = int(math.pow(2, host_bit))
    print ("Add ", hosts, " hosts to ", ip)
    return check_valid(int2ip(ip2int(ip) + hosts))

def ip2int(addr):
    ret = 0
    try:
        ret = struct.unpack("!I", socket.inet_aton(addr))[0]
    except:
        ret = 0
    return ret

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def signal_handler(signal, frame):
    print ("You Pressed Ctrl+C")
    save_address(addrname, address)
    save_organization(orgname, organizations)
    sys.exit(0)

def init_address(addrname):
    if not os.path.exists(addrname):
        return {}

    f = open(addrname, "r")
    f.readline()
    for line in f:
        tmp = line.strip().split(", ")
        if len(tmp) >= 2:
            address[ip2int(tmp[0].strip())] = tmp[1].strip()
    f.close()

def init_organizations(orgname):
    if not os.path.exists(orgname):
        return {}

    f = open(orgname, "r")
    for line in f:
        tmp = line.strip().split(", ")
        rank = int(tmp[0])
        dom = tmp[1]
        try:
            orgs = tmp[2].split("_")
            organizations[rank] = (dom, orgs)
        except:
            continue
    f.close()

cloudflare_start = ip2int("104.16.0.0")
cloudflare_end = ip2int("104.31.255.255")

def get_organizations(addr):
    ret = None

    try:
        ret = address[addr]
    except:
        ret = None

        if addr >= cloudflare_start and addr <= cloudflare_end:
            ret = "Cloudflare,Inc."

    return ret

def check_unknown(fname, ofname, address, organizations):
    of = open(ofname, "w")
    dirs = sorted([d for d in os.listdir(".") if os.path.isdir(d)])
    
    path = fname

    total = {}
    f = open(path, "r")
    pre = "0"
    count = 0
    for line in f:
        tmp = line.strip().split(", ")
        curr = tmp[0].strip()

        if pre != curr:
            total[pre] = count
            pre = curr
            count = 0

        if "Unknown" in line or "RIPE Network" in line:
            count += 1
    total[pre] = count
    f.close()

    full = 0
    for k in total:
        full += total[k]

    f = open(path, "r")

    pre_dt = "0"
    count = 0
    current = 0
    pre_clk = time.perf_counter()
    for line in f:
        tmp = line.strip().split(", ")

        if len(tmp) < 4:
            continue

        if not ("Unknown" in line or "RIPE Network" in line):
            of.write(line)
            continue

        dt = (tmp[0])
        rank = int(tmp[1])
        name = tmp[2]
        addr = tmp[3]

        if pre_dt != dt:
            curr_clk = time.perf_counter()
            elapsed_time = curr_clk - pre_clk
            print ("%s: %f" % (pre_dt, elapsed_time))
            pre_dt = dt
            pre_clk = curr_clk
            count = 0
            current += total[dt]
        count += 1

        if rank not in organizations:
            organizations[rank] = (name, [])

        organization = get_organizations(ip2int(addr))

        if organization:
            s = "%s, %s, %s, %s, %s" % (dt, rank, name, addr, organization)
        else:
            try:
                organization_lst = []
                process = subprocess.Popen(["timeout", "5", "dig", "-x", addr], stdout=subprocess.PIPE)
                output = process.communicate()[0].decode('utf8').split("\n")

                for elem in output:
                    if "\tPTR\t" in elem:
                        tmp = elem.split("\t")[-1].split(".")
                        organization = '.'.join(tmp[-3:])

                s = "%s, %s, %s, %s, %s" % (dt, rank, name, addr, organization)

                if organization != " ":
                    address[ip2int(addr)] = organization
            except:
                organization = "Error"
                s = "%s, %s, %s, %s" % (dt, rank, name, addr)

        if organization != "Unknown" and organization not in organizations[rank][1]:
            organizations[rank][1].append(organization)

        print ("%s [%d/%d]" % (s, count, total[dt]))
        of.write(s + "\n")
        #time.sleep(1)
       
    f.close()
    print ("========================\n")
    
    of.close()

def save_address(addrname, address):
    of = open(addrname, "w")
    for k in address:
        of.write("%s, %s\n" % (int2ip(int(k)), address[k]))

    of.close()

def save_organizations(orgname, organizations):
    of = open(orgname, "w")
    klst = sorted(organizations.keys())

    for rank in klst:
        dom = organizations[rank][0]
        lst = organizations[rank][1]

        try:
            orgs = "_".join(lst)
            s = "%d, %s, %s\n" % (rank, dom, orgs)
        except:
            s = "%d, %s\n" % (rank, dom)

        of.write(s)

    of.close()

def main():
    if len(sys.argv) != 5:
        usage()

    fname = sys.argv[1]
    ofname = sys.argv[2]
    addrname = sys.argv[3]
    orgname = sys.argv[4]

    signal.signal(signal.SIGINT, signal_handler)
    init_address(addrname) # IP address to organization
    init_organizations(orgname)
    check_unknown(fname, ofname, address, organizations)
    save_address(addrname, address)
    save_organizations(orgname, organizations)

if __name__ == "__main__":
    main()
