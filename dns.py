import socket
import glob
import json

host = ""
port = 53

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((host, port))

def load_zones():
    jsonzone = {}
    zonefiles = glob.glob("zones/*.zone")
    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data
    return jsonzone

zonedata = load_zones()

def getflags(flags, errors=False):
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])
    rflags = ""
    QR = "1"
    OPCODE = ""
    for bit in range(1, 5):
        OPCODE += str(ord(byte1) & (1 << bit))
    AA = "1"
    TC = "0"
    RD = "0"
    RA = "0"
    Z = "000"
    if errors:
        RCODE = "0003"
    else:
        RCODE = "0000"
    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder="big")+int(RA+Z+RCODE).to_bytes(1, byteorder="big")

def getquestiondomain(data):
    state = 0
    expectedlength = 0
    domainstring = ""
    domainparts = []
    x = 0
    y = 0
    for byte in data:
        if state == 1:
            domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                if not domainstring == "www":
                    domainparts.append(domainstring)
                domainstring = ""
                state = 0
                x = 0
            if byte == 0:
                break
        else:
            state = 1
            expectedlength = byte
        y += 1

    questiontype = data[y:y+2]

    return (domainparts, questiontype)

def getzone(domain):
    global zonedata
    zone_name = ".".join(domain) + "."
    try:
        zone = zonedata[zone_name]
        return zone
    except KeyError:
        return False


def getrecs(data):
    domain, questiontype = getquestiondomain(data)
    qt = ""
    if questiontype == b"\x00\x01":
        qt = "a"
    print("Searching for " + ".".join(domain))
    zone = getzone(domain)
    if zone == False:
        print("- Not found")
        return (False, qt, domain)
    else:
        print("- Found")
        return (zone[qt], qt, domain)

def buildquestion(domainname, rectype):
    qbytes = b""
    for part in domainname:
        length = len(part)
        qbytes += bytes([length])
        for char in list(part):
            qbytes += ord(char).to_bytes(1, byteorder="big")
    qbytes += (0).to_bytes(1, byteorder="big")
    if rectype == "a":
        qbytes += (1).to_bytes(2, byteorder="big")
    qbytes += (1).to_bytes(2, byteorder="big")
    return qbytes

def rectobytes(domainname, rectype, recttl, recval):
    rbytes = b"\xc0\x0c"
    if rectype == "a":
        rbytes = rbytes + bytes([0]) + bytes([1])
    rbytes = rbytes + bytes([0]) + bytes([1])
    rbytes += int(recttl).to_bytes(4, byteorder="big")
    if rectype == "a":
        rbytes = rbytes + bytes([0]) + bytes([4])

        for part in recval.split("."):
            rbytes += bytes([int(part)])
    return rbytes

def buildresponse(data):
    # Transaction ID
    TransactionID = data[:2]

    records, rectype, domainname = getrecs(data[12:])

    # Get the flags
    if records == False:
        Flags = getflags(data[2:4], errors=True)
    else:
        Flags = getflags(data[2:4], errors=False)
    # Question Count
    QDCOUNT = b"\x00\x01"

    # Answer count
    if not records:
        ANCOUNT = (0).to_bytes(2, byteorder="big")
    else:
        ANCOUNT = len(records).to_bytes(2, byteorder="big")

    # Nameserver count
    NSCOUNT = (0).to_bytes(2, byteorder="big")

    # Additional count
    ARCOUNT = (0).to_bytes(2, byteorder="big")

    dnsheader = TransactionID+Flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT


    # Create dns body
    dnsbody = b""


    dnsquestion = buildquestion(domainname, rectype)

    if not records:
        dnsbody = b""
    else:
        for record in records:
            dnsbody += rectobytes(domainname, rectype, record["ttl"], record["value"])

    return dnsheader + dnsquestion + dnsbody



while 1:
    try:
        data, addr = sock.recvfrom(512)
        print(addr[0] + " sent a request!")
        r = buildresponse(data)
        sock.sendto(r, addr)
        print("------------------------")
    except:
        continue
