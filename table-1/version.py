import sys
import os

log_files = [("tls1_0.csv", 0), ("tls1_1.csv", 1), ("tls1_2.csv", 2), ("tls1_3_23.csv", 23), ("tls1_3.csv", 3), ("others.csv", -1), ("error.csv", -2)]

def usage():
    print ("Analyze the highest TLS version of domains")
    print ("python3 version.py <output file name>")
    print ("This script should be on the root directory of the version information")
    exit(1)

def analyze(version):
    dirs = sorted([d for d in os.listdir(".") if os.path.isdir(d)])
    print (dirs)
    
    for d in dirs:
        print ("\n========== %s ==========" % d)
        for lf in log_files:
            path = "%s/%s" % (d, lf[0])
            print (path)

            try:
                f = open(path, "r")

                for line in f:
                    tmp = line.strip().split(",")
                    rank = int(tmp[1])
                    dt = tmp[0]
                
                    if len(version[rank]) == 0:
                        version[rank].append((dt, lf[1]))
                    elif version[rank][-1][1] != lf[1]:
                        if (lf[1] >= 0):
                            version[rank].append((dt, lf[1]))
            except:
                continue
    
        print ("========================\n")
        
def save_file(of, version):
    for i in range(1, 1000001):
        lst = version[i]
        lst = sorted(lst, key=lambda lst:lst[0])
        s = "%d" % i

        for e in lst:
            s += ", %s:%d" % (e[0], e[1])

        s += "\n"
        of.write(s)

def main():
    if len(sys.argv) != 2:
        usage()

    ofname = sys.argv[1]
    of = open(ofname, "w")

    version = {}
    for i in range(1, 1000001):
        version[i] = []

    analyze(version)
    save_file(of, version)

if __name__ == "__main__":
    main()
