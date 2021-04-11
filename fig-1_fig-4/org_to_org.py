import sys
import os

def usage():
    print ("Translate the organization to the organization")
    print ("python3 org_to_org.py <input file> <output file> <org to org map>")
    exit(1)

def init_org_to_org(name):
    d = {}

    f = open(name, "r")
    for line in f:
        tmp = line.strip().split(", ")
        d[tmp[0]] = tmp[1]
    f.close()

    return d

def run_org_to_org(fname, ofname, o):
    f = open(fname, "r")
    of = open(ofname, "w")

    for line in f:
        tmp = line.strip().split(", ")
        s = line

        if len(tmp) == 6:
            if tmp[4] in o:
                s = "%s, %s, %s, %s, %s, %s\n" % (tmp[0], tmp[1], tmp[2], tmp[3], o[tmp[4]], tmp[5])
        of.write(s)
    f.close()
    of.close()

def main():
    if len(sys.argv) != 4:
        usage()

    fname = sys.argv[1]
    ofname = sys.argv[2]
    oname = sys.argv[3]

    o = init_org_to_org(oname)
    run_org_to_org(fname, ofname, o)

if __name__ == "__main__":
    main()
