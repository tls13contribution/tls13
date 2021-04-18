import argparse
import os
import shutil

def prepare(fname):
    if not os.path.exists("dataset"):
        os.makedirs("dataset")
    
    if not os.path.exists("log"):
        os.makedirs("log")

    name = fname.strip().split("/")[-1]
    print ("name: {}".format(name))
    num = int(name.split(".")[0])
    tname = "dataset/{}".format(name)
    shutil.copy(fname, tname)

    lname = "log/last_domain_{}".format(num)
    copy = False

    if os.path.exists(lname):
        with open(lname, "r") as l:
            r, d = l.readline().strip().split(",")

        with open(tname, "w") as t:
            with open(fname, "r") as f:
                for line in f:
                    rank, dom = line.strip().split(",")
                    if rank == r:
                        copy = True
                        line = f.readline()

                    if copy:
                        t.write(line)

    return tname

def ping(fname, ofname, trial):
    f = open(fname, "r")
    of = open(ofname, "a")
    num = int(fname.split("/")[-1].split(".")[0])
    lname = "log/last_domain_{}".format(num)

    for line in f:
        tmp = line.strip().split(",")
        rank = int(tmp[0])
        dom = tmp[1]
        cmd = "ping -c {} -i 0.2 -W 2 {}".format(trial, dom)
        p = os.popen(cmd).read()
        result = p.split("=")[-1].strip().split(" ")[0].split("/")
        s = "{},{},{}\n".format(rank, dom, ','.join(result))
        of.write(s)
        l = open(lname, "w")
        l.write(line)
        l.close()

    f.close()
    of.close()

def main():
    args = parser.parse_args()
    print ("input filename: {}".format(args.input))
    print ("output filename: {}".format(args.output))
    print ("number of pings: {}".format(args.trial))

    tname = prepare(args.input)
    print ("target filename: {}".format(tname))
    ping(tname, args.output)

if __name__ == "__main__":
    global parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", metavar="<input file name>", help="input file name", required=True, type=str)
    parser.add_argument("-o", "--output", metavar="<output file name>", help="output file name", required=True, type=str)
    parser.add_argument("-t", "--trial", metavar="<number of pings>", help="number of pings", type=int, default=10)
    main()
