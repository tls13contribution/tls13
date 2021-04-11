import sys
import os

def usage():
    print ("Translate the domain to the organization")
    print ("python3 dom_to_org.py <input file> <output file> <dom to org map>")
    exit(1)

def init_dom_to_org(dname):
    d = {}
    df = open(dname, "r")
    
    for line in df:
        tmp = line.strip().split(", ")
        d[tmp[0]] = tmp[1]

    return d

def run_dom_to_org(fname, ofname, d, org):
    f = open(fname, "r")
    of = open(ofname, "w")

    for line in f:
        tmp = line.strip().split(", ")
        dom = tmp[-1].split(".")

        if len(dom) > 2:
            if tmp[-1] in d:
                s = "%s, %s, %s, %s, %s, %s\n" % (tmp[0], tmp[1], tmp[2], tmp[3], d[tmp[-1]], org[d[tmp[-1]]])
            else:
                s = "%s, None\n" % line.strip()
        else:
            if tmp[-1] in org:
                s = "%s, %s\n" % (line.strip(), org[tmp[-1]])
            else:
                s = "%s, None\n" % line.strip() 
        of.write(s)
    f.close()
    of.close()

def init_dom_to_org(dname):
    d = {}
    org = {}

    f = open(dname, "r")
    for line in f:
        tmp = line.strip().split(", ")
        d[tmp[0]] = tmp[1]
        org[tmp[1]] = tmp[2]
    f.close()

    return d, org

def main():
    if len(sys.argv) != 4:
        usage()

    fname = sys.argv[1]
    ofname = sys.argv[2]
    dname = sys.argv[3]

    d, org = init_dom_to_org(dname)
    run_dom_to_org(fname, ofname, d, org)

if __name__ == "__main__":
    main()
