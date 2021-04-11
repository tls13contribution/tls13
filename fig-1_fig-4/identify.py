import argparse

def load_ip_addr_reference(iname):
    ret = {}

    with open(iname, "r") as f:
        for line in f:
            tmp = line.strip().split(", ")
            rank = int(tmp[0])
            result = tmp[2]

    return ret

def load_anycast_reference(aname):
    ret = {}

    with open(aname, "r") as f:
        for line in f:
            tmp = line.strip().split(",")
            rank = int(tmp[0])
            result = tmp[2].strip()
            ret[rank] = result

    return ret

def platform_identification(fname, ofname, anycast, ipaddr):
    ret = {}
    of = open(ofname, "w")

    with open(fname, "r") as f:
        for line in f:
            classified = None
            tmp = line.strip().split(", ")
            dt = tmp[0]
            rank = int(tmp[1])
            platform = tmp[-1]

            if not dt in ret:
                ret[dt] = {}
                ret[dt]["fpr"] = 0
                ret[dt]["tpr"] = 0

            if platform == "Cloud Platform":
                ret[dt]["fpr"] = ret[dt]["fpr"] + 1
                classified = "First"
            elif platform == "Cloud Platform/Web Hosting":
                ret[dt]["fpr"] = ret[dt]["fpr"] + 1
                classified = "First"
            elif platform == "Web Hosting/Cloud Platform":
                ret[dt]["fpr"] = ret[dt]["fpr"] + 1
                classified = "First"
            elif platform == "Own Platform":
                ret[dt]["fpr"] = ret[dt]["fpr"] + 1
                classified = "First"
            elif "CDN Platform" == platform:
                ret[dt]["tpr"] = ret[dt]["tpr"] + 1
                classified = "Third"
            elif "Web Hosting" == platform:
                ret[dt]["tpr"] = ret[dt]["tpr"] + 1
                classified = "Third"
            elif "Security Platform" == platform:
                ret[dt]["tpr"] = ret[dt]["tpr"] + 1
                classified = "Third"

            elif "None" in platform:
                if rank in ipaddr and rank in anycast:
                    if ipaddr[rank] == "Same" and anycast[rank] == "Short":
                        ret[dt]["tpr"] = ret[dt]["tpr"] + 1
                        classified = "Third"
                    elif ipaddr[rank] == "Different" and anycast[rank] == "Long":
                        ret[dt]["fpr"] = ret[dt]["fpr"] + 1
                        classified = "First"
                elif rank not in ipaddr and rank in anycast:
                    if anycast[rank] == "Long":
                        ret[dt]["fpr"] = ret[dt]["fpr"] + 1
                        classified = "First"
                    else:
                        ret[dt]["tpr"] = ret[dt]["tpr"] + 1
                        classified = "Third"
                else:
                    if rank not in ipaddr:
                        print ("Not in ipaddr")
                    else:
                        print ("Result: {}".format(ipaddr[rank]))

                    if rank not in anycast:
                        print ("Not in anycast")
                    else:
                        print ("Result: {}".format(anycast[rank]))


                    print (line)
                    break
            else:
                print (line)
                break

            of.write("{}, {}\n".format(line.strip(), classified))
    of.close()

    return ret

def save_result(ofname, result):
    dts = sorted(result.keys())
    with open(ofname, "w") as of:
        for dt in dts:
            of.write("{}\n".format(dt))
            total = result[dt]["fpr"] + result[dt]["tpr"]
            of.write("First Party, {}, {}%\n".format(result[dt]["fpr"], round(result[dt]["fpr"] * 100 /total, 2)))
            of.write("Third Party, {}, {}%\n".format(result[dt]["tpr"], round(result[dt]["tpr"] * 100 /total, 2)))

def command_line_args():
    parser = argparse.ArgumentParser(description='first party/third party identification')
    parser.add_argument("-i", "--input", metavar="<TLS 1.3 websites>", required=True, type=str)
    parser.add_argument("-o", "--output", metavar="<output file name>", required=True, type=str)
    parser.add_argument("-a", "--anycast", metavar="<anycast reference file>", required=True, type=str)
    parser.add_argument("-b", "--ipaddr", metavar="<ip address reference file>", required=True, type=str)
    args = parser.parse_args()

    return args

def main():
    args = command_line_args()

    anycast = load_anycast_reference(args.anycast)
    addr = load_ip_addr_reference(args.ipaddr)

    ret = platform_identification(args.input, "tmp", anycast, addr)
    save_result(args.output, ret)

if __name__ == "__main__":
    main()
