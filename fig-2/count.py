from struct import *
import sys
import os
import glob
import time
from ciph import ciphersuite

content_type = {20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23:
'Application Data'}
major = {0x03: 1}
minor = {0x00:-1, 0x01: 0, 0x02: 1, 0x03: 2}

handshake_type = {0: 'Hello Request', 1: 'Client Hello', 2: 'Server Hello'}
extension_type = {
        0xff01: 'Renegotiation Info', 
        0x0000: 'Server Name', 
        0x0001: 'Max Fragment Length',
        0x0002: 'Client Certificate URL',
        0x0003: 'Trusted CA Keys',
        0x0004: 'Truncated HMAC',
        0x0005: 'Status Request',
        0x0006: 'User Mapping',
        0x0007: 'Client Authz',
        0x0008: 'Server Authz',
        0x0009: 'Cert Type',
        0x000a: 'Supported Groups',
        0x000b: 'EC Point Formats',
        0x000c: 'Server Remote Password',
        0x000d: 'Signature Algorithms',
        0x000e: 'Use SRTP',
        0x000f: 'Heartbeat',
        0x0010: 'Application Layer Protocol Negotiation',
        0x0012: 'Signed Certificate Timestamp',
        0x0015: 'Padding',
        0x0016: 'Encrypt Then MAC',
        0x0017: 'Extended Master Secret',
        0x0023: 'Session Ticket',
        0x0029: 'Preshared Key',
        0x002a: 'Early Data',
        0x002b: 'Supported Version',
        0x002c: 'Cookie',
        0x002d: 'Preshared Key Exchange Modes',
        0x002f: 'Certificate Authorities',
        0x0031: 'Post Handshake Auth',
        0x0032: 'Signature Algorithms Certificate',
        0x0033: 'Key Share',
        13172: 'Next Protocol Negotiation'
        }

class RecordHeader:
    def __init__(self, buf):
        ct, ma, mi, self.length = unpack('>BBBH', buf)
        self.contentType = content_type[ct]
        self.major = major[ma]
        self.minor = minor[mi]

    def calcLength(self, l2, l1):
        return (l2 << 8) | l1

    def printContent(self):
        print("Content Type: ", self.contentType)
        print("Version: TLS %d.%d" % (self.major, self.minor))
        print("Length: ", self.length)

class Hello:
    def __init__(self, buf, server):
        self.handshakeType = ""
        self.length = 0
        self.major = 0
        self.minor = 0
        self.sIDLen = 0
        self.cipherLen = 0
        self.ciphersuites = []
        self.compLen = 0
        self.extLen = 0
        self.extensions = []
        self.extensionsLen = []
        self.values = []
        self.hasSupportedVersion = False
        self.retValue = -1
        self.draft = False
        self.draftVersion = 0

        offset = 0
        ht, l3, l2, l1, ma, mi = unpack('>BBBBBB',
                buf[offset:offset+6])
        self.handshakeType = handshake_type[ht]
        self.length = (l3 << 16) | (l2 << 8) | l1
        self.major = major[ma]
        self.minor = minor[mi]

        if self.major == 1:
            self.retValue = self.minor
        else:
            self.retValue = -1

        offset = offset + 6
        offset = offset + 32 # random
        #print ("sIDLen: %x" % (buf[offset]))
        self.sIDLen = int(buf[offset])
        offset = offset + 1 # session id length
        offset = offset + self.sIDLen # session id
        
        if server:
            # the length of the list of ciphersuites
            self.cipherLen = 2
            self.ciphersuites.append(unpack('>H', buf[offset:offset+2]))
            offset += 2
        else:
            # the length of the list of ciphersuites
            self.cipherLen = unpack('>H', buf[offset:offset+2])[0]
            offset += 2
            tmp = self.cipherLen

            while tmp > 0:
                self.ciphersuite.append(unpack('>H', buf[offset:offset+2]))
                tmp -= 2
                offset += 2

        if server:
            self.compLen = 1
        else:
            self.compLen = buf[offset]
            offset = offset + 1
        offset = offset + self.compLen

        if offset < self.length:
            self.extLen = unpack('>H', buf[offset:offset+2])[0]
            offset = offset + 2
            num = self.extLen

            while num > 0:
                ext = unpack('>H', buf[offset:offset+2])[0]
                offset = offset + 2

                try:
                    self.extensions.append(extension_type[ext])
                except:
                    self.extensions.append("Unknown: %d" % ext)
                l = unpack('>H', buf[offset:offset+2])[0]

                self.extensionsLen.append(l)
                offset = offset + 2
                value = buf[offset:offset+l]
                self.values.append(value)

                if ext == 0x002b:
                    self.hasSupportedVersion = True
                    if l == 2:
                        num_of_bytes = 2
                        off = 0
                    else:
                        num_of_bytes = int(value[0])
                        off = 1

                    #print (value, " length: ", num_of_bytes, " ret value: ", self.retValue)
                    while num_of_bytes > 0:
                        try:
                            tmp = unpack('>H', value[off:off+2])[0]
                            if tmp & 0xff00 == 0x7f00:
                                self.draft = True
                                self.draftVersion = (tmp & 0x00ff)
                                self.retValue = self.draftVersion
                            elif tmp == 0x0304 and self.retValue < 3:
                                self.retValue = 3
                            elif tmp == 0x0303 and self.retValue < 2:
                                self.retValue = 2
                            elif tmp == 0x0302 and self.retValue < 1:
                                self.retValue = 1
                            elif tmp == 0x0301 and self.retValue < 0:
                                self.retValue = 0
                        except:
                            self.retValue = -1

                        off = off + 2
                        num_of_bytes = num_of_bytes - 2

                offset = offset + l
                num = num - 2 - 2 - l
        else:
            self.retValue = -1

    def printContent(self):
        print("Handshake Type: ", self.handshakeType)
        print("Length: ", self.length)
        print("Version: TLS %d.%d" % (self.major, self.minor))
        print("Session ID Length: ", self.sIDLen)
        print("Length of Ciphersuite: ", self.cipherLen)
        print("Length of Compression: ", self.compLen)
        print("Length of Extension: ", self.extLen)
        num = len(self.extensions)
        for i in range(num):
            print(self.extensions[i], "(", self.extensionsLen[i], "): ", self.values[i])

    def getReturn(self):
        return self.retValue

    def getDraftVersion(self):
        return self.draftVersion

    def getSelectedCiphersuite(self):
        return self.ciphersuites[0][0]

def usage():
    print("Usage: Count the frequency for each TLS version")
    print("python3 count_version.py <directory>")
    exit(1)

def analysis(log_file):
    f = open(log_file, "rb")
    ret = -1
    dver = 0

    while True:
        line = f.readline().decode().split(":")
        if (not line) or (len(line) < 2):
            ret = -1
            break
        elif "Server" not in line[0]:
            hlen = int(line[1])
            f.seek(hlen, 1)

            if (f.tell() != os.fstat(f.fileno()).st_size):
                f.seek(1, 1)
            else:
                ret = -1
                break
        else:
            sh_len = int(line[1])

            if sh_len < 6:
                ret = -1
                break

            sh_buf = f.read()[0:sh_len]
            sh = Hello(sh_buf, 1)
            #sh.printContent()
            ret = sh.getReturn()
            dver = sh.getDraftVersion()
            ciph = sh.getSelectedCiphersuite()
            break

    return ret, dver, ciph

def main():
    if len(sys.argv) != 2:
        usage()

    start = time.time()
    d = sys.argv[1]
    ofname = "%s.csv" % d
    of = open(ofname, "w")
    total = 0
    ver0 = 0
    ver1 = 0
    ver2 = 0
    ver3 = 0
    ver23 = 0
    draft = {}
    err = 0
    others = 0

    f0 = open("%s_tls1_0.csv" % d, "w")
    f1 = open("%s_tls1_1.csv" % d, "w")
    f2 = open("%s_tls1_2.csv" % d, "w")
    f30 = open("%s_tls1_3.csv" % d, "w")
    f323 = open("%s_tls1_3_23.csv" % d, "w")
    e = open("%s_err.csv" % d, "w")
    o = open("%s_other.csv" % d, "w")



    for root, dirs, files in os.walk(d):
        for di in dirs:
            if di == ".":
                continue
            lst =  glob.glob("%s/%s/*.log" % (d, di))

            for f in lst:
                total = total + 1
                ret, dver, sciph = analysis(f)
                print (total, ") Filename: ", f, " Return: ", ret, ", ", dver)
                if ret == 0:
                    ver0 = ver0 + 1
                    f0.write(f)
                    f0.write("\n")
                elif ret == 1:
                    ver1 = ver1 + 1
                    f1.write(f)
                    f1.write("\n")
                elif ret == 2:
                    ver2 = ver2 + 1
                    f2.write(f)
                    f2.write("\n")
                elif ret == 3:
                    ver3 = ver3 + 1
                    f30.write(f)
                    f30.write("\n")
                elif ret == 23:
                    ver23 = ver23 + 1
                    f323.write(f)
                    f323.write("\n")
                elif ret == -1:
                    err = err + 1
                else:
                    others = others + 1

    end = time.time()
    s1 = "Total, TLSv1.3, TLSv1.3 (draft 23), TLSv1.2, TLSv1.1, TLSv1.0, Error, Others, Connection Failed\n"
    s2 = "%d, %d, %d, %d, %d, %d, %d, %d, %d" % (total, ver3, ver23, ver2, ver1, ver0, err, others, 1000000 - total)
    print (s1)
    print (s2)
    of.write(s1)
    of.write("\n")
    of.write(s2)
    of.write("\n")
    print ("Elapsed Time: %f" % (end - start))

    of.close()
    f0.close()
    f1.close()
    f2.close()
    f30.close()
    f323.close()
    e.close()
    o.close()

if __name__ == "__main__":
    main()
