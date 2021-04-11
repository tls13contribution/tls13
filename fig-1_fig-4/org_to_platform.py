import sys
import os

def usage():
    print ("Translate the domain to the organization")
    print ("python3 org_to_platform.py <input file> <output file> <org to platform map>")
    exit(1)

def init_org_to_platform(name):
    d = {}

    f = open(name, "r")
    for line in f:
        tmp = line.strip().split(", ")
        d[tmp[0]] = tmp[1]
    f.close()

    return d

def run_org_to_platform(fname, ofname, p):
    f = open(fname, "r")
    of = open(ofname, "w")

    for line in f:
        tmp = line.strip().split(", ")
        dom = tmp[-1].split(".")

        s = line
        if len(tmp) == 6:
            if tmp[4] in p:
                s = "%s, %s, %s, %s, %s, %s\n" % (tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], p[tmp[4]])
        of.write(s)
    f.close()
    of.close()

def main():
    if len(sys.argv) != 4:
        usage()

    fname = sys.argv[1]
    ofname = sys.argv[2]
    pname = sys.argv[3]

    p = init_org_to_platform(pname)
    run_org_to_platform(fname, ofname, p)

if __name__ == "__main__":
    main()
