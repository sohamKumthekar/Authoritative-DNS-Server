#DNS uses udp protocol upto 512 bytes (fast)
#to identify if the response sent by the serv ef was correct - transaction id is used
#DNS headers are 12 bytes long - from 13th byte is the actual message
#DNS compresses the response message - to avoid the repitition of domain name in the message and to save bandwidth
#repeated domain name is replaced with the POINTER which points to the first occurence of the name
#pointer - seq of 2 octets - its decimal conversion(excluding 1st 2 bits) gives number of bytes from starting of req where that name appeared 1st time


import json
import socket, glob
#by default DNS operates on port 53 - port less than 80 requires sudo permission
port = 59
ip = "127.0.0.1"

#use IPv4, UDP - create socket and bind it with specified port number
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))


def load_zones():

    jsonzone = {}

    #extract from zones folder
    zonefiles = glob.glob('zones/*.zone')
    # print(zonefiles)

    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"] #origin contains domain name
            jsonzone[zonename] = data

    return jsonzone         

zonedata = load_zones()

#2 bytes of flag
def getflags(flags):
    rflags = ''  #response fags

    #first flag bit = 1(for response)
    QR = '1'

    #seperate 2 bytes of flag
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])

    #4 bits opcode
    OPCODE = ''
    for bit in range(1,5):
        #to get indivisual 4 bits in the opcode from first byte
        OPCODE += str(ord(byte1) & (1 << bit))



    AA = '1'  #designing authoritative server
    TC = '0'  #message wasn't truncated - length was within transmission channel capacity
    RD = '0'  #not recursive

    #Byte 2
    RA = '0'    #recursion available 
    Z = '000'  #reserved for future use - must be zero in query and response
    RCODE = '0000'   #no error condition

    #big - big endian byte ordering - MSB at start
    # flags_byte1 =  int(QR + OPCODE + AA + TC + RD).to_bytes(1, byteorder='big')
    # flags_byte2 =  int(RA + Z + RCODE).to_bytes(1, 'big')
    
    
    return int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder='big') + int(RA + Z + RCODE, 2).to_bytes(1, byteorder='big')


#to get the domain name being queried
def getquestiondomain(data):
    state  = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []    #if domain name has multiple words
    x = 0
    y = 0

    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            
            #end of the string (0 indicates the end of domoain name in query)
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expectedlength = byte #first byte is length of the expected length
        # x += 1
        y += 1  #to keep track of last byte number in domain name
        # print(domainparts)

    #after domain name, next 2 bytes are type of the query
    questiontype = data[y : y+2]
 
    print(questiontype)

    return(domainparts, questiontype)


def getzone(domain):
    #zonedata is dic containing data as value with domain name key
    #zonedata = {zonename : {'origin' : , 'a' : , }} 
    global zonedata

    #get the zone name by combining the parts of domain name
    zone_name = '.'.join(domain) 
    return zonedata[zone_name]

#get records from zone files using the obtained domain name and question type   
def getrecs(data):
    #domain is list of domain parts
    domain, questiontype = getquestiondomain(data)
    qt = ''

    #if question type is a in query - it is encoded as 1
    if questiontype == b'\x00\x01':
        qt = 'a'

    #get the entire data
    zone = getzone(domain)

    #zone[qt] - only value of key indicating question type
    return (zone[qt], qt, domain)

def buildquestion(domainname, rectype):
    #3 parts of question - QNAME, QTYPE(a here), QCLASS(IN for internet)

    qbytes = b''
    
    #domainname - list of domain name parts
    for part in domainname:
        length = len(part)
        qbytes += bytes([length])
    # print(qbytes)

        for char in part:
            qbytes = ord(char).to_bytes(1, byteorder='big')

    #adding QTYPE (2 bytes)
    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')

    #Adding for QCLASS = IN (2 bytes)
    qbytes += (1).to_bytes(2, byteorder='big')

    return qbytes

#get the ANSWER fields - 
def rectobytes(domainname, rectype, recttl, recval):
    #compressed version of the domain name (c0 0c for howcode.org)
    #NAME(2 bytes)
    rbytes = b'\xc0\x0c'

    #TYPE(2bytes)
    if rectype == 'a':
        #\x01 for type 'a
        rbytes = rbytes + bytes([0]) + bytes([1])

    #add CLASS (2 bytes)
    rbytes = rbytes + bytes([0]) + bytes([1])
      
    #add TTL (4 bytes)
    # specifies the time
    # interval (in seconds) that the resource record may be
    # cached before it should be discarded
    rbytes = rbytes + int(recttl).to_bytes(4, byteorder='big')

    #add RDLENGTH (2 bytes)
    #gives length of next field RDATA in number of octest(4 here)
    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])   #\x0\x4

        for part in recval.split('.'):
            rbytes += bytes([int(part)])
    return rbytes



def buildresponse(data):
    #get the transaction ID
    #first 2 bytes from DNS query is transaction ID (byte string)
    transaction_ID = data[0:2]
    # TID = ''
    # for byte in transaction_ID:
    #     TID += hex(byte)[2:]

    #get the Flags (bytes 2 and 3 are flags)
    Flags = getflags(data[2:4])
    print(Flags)

    #Question count(usualy 1)- 2 bytes
    QDCOUNT = b'\x00\x01'

    #Answer count
    #actual query starts from byte no. 13 (1st 12 are header)
    #to get the domain name being queried
    #starts from byte 13
    #getquestiondomain(data[12:]) 

    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')
    print(ANCOUNT)

    #Name server count
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    #Additional count
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    #final header
    dnsheader = transaction_ID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    print("DnS header : \n",dnsheader)

    #creating DNS body
    dnsbody = b''
    
    #exclude the header
    #get answer for query
    records, rectype, domainname = getrecs(data[12:])
    #records - [{}, {}, {}]

    #next field after header
    dnsquestion = buildquestion(domainname,rectype)
    # print(dnsquestion)

    #next field is ANSWER - 
    for record in records:
        dnsbody += rectobytes(domainname, rectype, record["ttl"], record["value"])


    return dnsheader + dnsquestion + dnsbody

while(1):
    #receive 512 bytes
    data , addr = sock.recvfrom(512)
    #build DNS response from data
    r = buildresponse(data)

    print("query:\n",data)

    sock.sendto(r, addr)
