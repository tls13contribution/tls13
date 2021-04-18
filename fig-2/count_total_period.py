import os
import sys
import count
import time
import glob
import signal
from ciph import ciphersuite

aead = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]

def usage():
    print("Usage: Count the frequency for each TLS version")
    print("python3 count_total.py <output file> <start date> <end date> <country>")
    exit(1)

def main():
    if len(sys.argv) != 5:
        usage()

    ofname = sys.argv[1]
    prefix = ofname.split(".")[0]
    cfname = "%s_cipher.csv" % prefix

    signal.signal(signal.SIGTERM, exit)

    start = sys.argv[2]
    end = sys.argv[3]
    country = sys.argv[4]
    done = []

    if not os.path.exists("ciphersuites"):
        os.mkdir("ciphersuites")

    if os.path.exists(ofname):
        f = open(ofname, "r")
        for line in f:
            tmp = line.strip().split(",")
            done.append("%s" % tmp[0].strip())
        f.close()
        of = open(ofname, "a")
    else:
        of = open(ofname, "w")
        of.write("Date, Total, TLSv1.3, TLSv1.3 (draft 23), TLSv1.2, TLSv1.1, TLSv1.0, Error, Others, Connection Failed\n")

    if os.path.exists(cfname):
        cf = open(cfname, "a")
    else:
        cf = open(cfname, "w")
        ctitle = "Date, Total"

        for k in ciphersuite:
            ctitle += ", %04x" % k

        ctitle += "\n"
        cf.write(ctitle)

    cfs = {}
    for k in ciphersuite:
        cfs[k] = open("ciphersuites/%04x.csv" % k, "w")

    f0 = open("tls1_0.csv", "w")
    f1 = open("tls1_1.csv", "w")
    f2 = open("tls1_2.csv", "w")
    f3 = open("tls1_3.csv", "w")
    f323 = open("tls1_3_23.csv", "w")
    fe = open("error.csv", "w")
    fo = open("others.csv", "w")
    version = open("{}.csv".format(country), "w")

    target = []

    target = [d for d in os.listdir(".") if os.path.isdir(d)]
    tmp_lst = target[:]

    for t in tmp_lst:
        if t in done:
            target.remove(t)
        if t < start:
            target.remove(t)
        if t > end:
            target.remove(t)

    target.sort()
    print (target)

    for t in target:
        total = 0
        ver0 = 0
        ver1 = 0
        ver2 = 0
        ver3 = 0
        ver23 = 0
        err = 0
        others = 0
        date = t
        num_of_ciph = {}

        domains = {}
        for i in range(1, 21):
            fname = "%s/ips_%d.csv" % (t, i)
            try:
                f = open(fname, "r")

                for line in f:
                    tmp = line.strip().split(", ")
                    try:
                        domains[int(tmp[0])] = (tmp[1], tmp[2]) # domains[rank] = (domain name, IP address)
                    except:
                        continue
        
                f.close()
            except:
                continue

        for k in ciphersuite:
            num_of_ciph[k] = 0

        for root, dirs, files in os.walk(t):
            for di in dirs:
                if di == ".":
                    continue
                lst = glob.glob("%s/%s/*.log" % (t, di))

                for f in lst:
                    num = int(f.strip().split("/")[-1].split(".")[0])

                    try:
                        name = domains[num][0]
                    except:
                        name = " "

                    try:
                        addr = domains[num][1]
                    except:
                        addr = " "

                    e = "%s, %d, %s, %s\n" % (date, num, name, addr)

                    try:
                        total = total + 1
                        ret, draft, sciph = count.analysis(f)
                        v = "{}, {}, {}, {}\n".format(num, name, addr, ret)
                        version.write(v)

                        num_of_ciph[sciph] += 1
                        cfs[sciph].write(e)

                        if ret == 0:
                            ver0 = ver0 + 1
                            f0.write(e)
                        elif ret == 1:
                            ver1 = ver1 + 1
                            f1.write(e)
                        elif ret == 2:
                            ver2 = ver2 + 1
                            f2.write(e)
                        elif ret == 3:
                            ver3 = ver3 + 1
                            f3.write(e)
                        elif ret == 23:
                            ver23 = ver23 + 1
                            f323.write(e)
                        elif ret == -1:
                            err = err + 1
                            fe.write(e)
                        else:
                            others = others + 1
                            fo.write(e)
                    except:
                        err = err + 1
                        fe.write(e)
                        continue

        s = "%s, %d, %d, %d, %d, %d, %d, %d, %d, %d\n" % (date, total, ver3, ver23, ver2, ver1, ver0, err, others, 1000000 - total)
        of.write(s)

        cf.write("%s, %d" % (date, total))
        cf.write("\n")

        mtitle = "Analysis is on going for %s" % t
        msg = "Result\nDate, Total, TLS 1.3, TLS 1.3 (draft), TLS 1.2, TLS 1.1, TLS 1.0, Errors, Others, Connection Failed\n%s" % s

    of.close()
    f0.close()
    f1.close()
    f2.close()
    f3.close()
    f323.close()
    fe.close()
    fo.close()
    version.close()

    for k in ciphersuite:
        cfs[k].close()

if __name__ == "__main__":
    main()
