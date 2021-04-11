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
import argparse
import logging
from unknown import check_unknown
from dom_to_org import init_dom_to_org, run_dom_to_org
from org_to_org import init_org_to_org, run_org_to_org
from org_to_platform import init_org_to_platform, run_org_to_platform
from identify import load_anycast_reference, load_ip_addr_reference, platform_identification, save_result

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

cloudflare_start = ip2int("104.16.0.0")
cloudflare_end = ip2int("104.31.255.255")

def signal_handler(signal, frame):
    print ("You Pressed Ctrl+C")
    save_address(addrname, address)
    save_organization(orgname, organizations)
    sys.exit(0)

def init_address(addrname):
    ret = {}

    if os.path.exists(addrname):
        with open(addrname, "r") as f:
            for line in f:
                tmp = line.strip().split(", ")
                ret[ip2int(tmp[0].strip())] = tmp[1].strip()

    return ret

def init_organizations(orgname):
    ret = {}

    if os.path.exists(orgname):
        with open(orgname, "r") as f:
            for line in f:
                tmp = line.strip().split(", ")
                rank = int(tmp[0])
                dom = tmp[1]
                try:
                    orgs = tmp[2].split("_")
                    ret[rank] = (dom, orgs)
                except:
                    continue

    return ret

def get_organizations(address, addr):
    ret = None

    try:
        ret = address[addr]
    except:
        ret = None

        if addr >= cloudflare_start and addr <= cloudflare_end:
            ret = "Cloudflare,Inc."

    return ret

def run_whois(fname, ofname, address, organizations):
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

        count += 1
    total[pre] = count
    f.close()

    full = 0
    for k in total:
        full += total[k]

    f = open(path, "r")
    uf = open("unknown", "w")

    pre_dt = "0"
    count = 0
    current = 0
    pre_clk = time.perf_counter()
    for line in f:
        tmp = line.strip().split(", ")

        if len(tmp) < 4:
            continue

        dt = (tmp[0])
        rank = int(tmp[1])
        name = tmp[2]
        addr = tmp[3]

        if pre_dt != dt:
            curr_clk = time.perf_counter()
            elapsed_time = curr_clk - pre_clk
            logging.debug("{}: {}".format(pre_dt, elapsed_time))
            pre_dt = dt
            pre_clk = curr_clk
            count = 0
            current += total[dt]
        count += 1

        if rank not in organizations:
            organizations[rank] = (name, [])

        organization = get_organizations(address, ip2int(addr))

        if organization:
            s = "{}, {}, {}, {}, {}\n".format(dt, rank, name, addr, organization)
        else:
            try:
                organization_lst = []
                process = subprocess.Popen(["timeout", "3", "whois", addr], stdout=subprocess.PIPE)
                output = process.communicate()[0].decode('utf8').replace("\t", "").split("\n")

                logging.debug("whois is used for {} ({})".format(name, addr))
                orgs = {}
                for elem in output:
                    if ":" not in elem:
                        continue
                    key = elem.split(":")[0].strip()

                    if "OrgName" in key or "org-name" in key or "descr" in key or "CustName" in key or "Organization" in key:
                        org = elem.split(":")[1].strip().replace(", ", ",")
                        orgs[key] = org

                if "OrgName" in orgs:
                    organization = orgs["OrgName"]
                elif "org-name" in orgs:
                    organization = orgs["org-name"]
                elif "CustName" in orgs:
                    organization = orgs["CustName"]
                elif "Organization" in orgs:
                    organization = orgs["Organization"]
                elif "descr" in orgs:
                    organization = orgs["descr"]
                else:
                    organization = "Unknown"
                    uf.write(line)
                s = "{}, {}, {}, {}, {}\n".format(dt, rank, name, addr, organization)

                if organization != " ":
                    address[ip2int(addr)] = organization
            except:
                organization = "Error"
                s = "{}, {}, {}, {}\n".format(dt, rank, name, addr)

        if organization != "Unknown" and organization not in organizations[rank][1]:
            organizations[rank][1].append(organization)

        if count % 3000 == 0:
            logging.info("[%d/%d]" % (count, total[dt]))
        of.write(s)
       
    f.close()
    logging.info("========================\n")
    
    of.close()
    uf.close()

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
        orgs = "_".join(lst)

        s = "{}, {}, {}\n".format(rank, dom, orgs)
        of.write(s)

    of.close()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", metavar="<input file name>", help="input file name", type=str, required=True)
    parser.add_argument("-o", "--output", metavar="<output file name>", help="output file name", type=str, required=True)
    parser.add_argument("-r", "--ratio", metavar="<first party to third party ratio file name>", help="first party to third party ratio file name", type=str, required=True)
    parser.add_argument("-a", "--address", metavar="<address cache file>", help="cache file that contains domain name-IP address mappings", type=str)
    parser.add_argument("-c", "--organization", metavar="<organization cache file>", help="cache file that contains domain name-organization mappings", type=str)
    parser.add_argument("-l", "--loglevel", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()

    fname = args.input
    ofname = args.output
    rfname = args.ratio
    addrname = args.address
    orgname = args.organization

    signal.signal(signal.SIGINT, signal_handler)
    logging.basicConfig(level=args.loglevel)

    if addrname:
        address = init_address(addrname) # IP address to organization
    else:
        address = {}

    if orgname:
        organizations = init_organizations(orgname)
    else:
        organizations = {}

    run_whois(fname, "tmp1", address, organizations)
    check_unknown("tmp1", "tmp2", address, organizations)

    d, org = init_dom_to_org("domain_organization")
    run_dom_to_org("tmp2", "tmp3", d, org)

    o = init_org_to_org("organization_organization")
    run_org_to_org("tmp3", "tmp4", o)

    p = init_org_to_platform("organization_platform")
    run_org_to_platform("tmp4", "tmp5", p)

    anycast = load_anycast_reference("anycast.csv")
    addr = load_ip_addr_reference("ipaddr.csv")

    ret = platform_identification("tmp5", ofname, anycast, addr)
    save_result(rfname, ret)

if __name__ == "__main__":
    main()
