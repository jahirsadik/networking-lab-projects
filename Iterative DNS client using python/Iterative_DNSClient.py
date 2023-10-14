from argparse import ArgumentParser
import random
import socket
import binascii
import socket
from collections import OrderedDict

# Root server names list
root_servers = ["a.root-servers.net", "b.root-servers.net", "c.root-servers.net",
                "d.root-servers.net", "e.root-servers.net", "f.root-servers.net",
                "g.root-servers.net", "h.root-servers.net", "i.root-servers.net",
                "j.root-servers.net", "k.root-servers.net", "l.root-servers.net",
                "m.root-servers.net"]

# Build the DNS message for a given type and address
# Other flag params are hardcoded as they're not needed for the task


def build_message(type="A", address=""):
    # 16-bit identifier (0-65535) # 43690 equals 'aaaa' (randomly chosen ID)
    ID = 43690

    QR = 0      # Query: 0, Response: 1     1bit
    OPCODE = 0  # Standard query            4bit
    AA = 0      # ?                         1bit
    TC = 0      # Message is truncated?     1bit
    RD = 1      # Recursion?                1bit
    RA = 0      # ?                         1bit
    Z = 0       # ?                         3bit
    RCODE = 0   # ?                         4bit

    query_params = str(QR)
    query_params += str(OPCODE).zfill(4)
    query_params += str(AA) + str(TC) + str(RD) + str(RA)
    query_params += str(Z).zfill(3)
    query_params += str(RCODE).zfill(4)
    query_params = "{:04x}".format(int(query_params, 2))

    QDCOUNT = 1  # Number of questions           4bit
    ANCOUNT = 0  # Number of answers             4bit
    NSCOUNT = 0  # Number of authority records   4bit
    ARCOUNT = 0  # Number of additional records  4bit

    message = ""
    message += "{:04x}".format(ID)
    message += query_params
    message += "{:04x}".format(QDCOUNT)
    message += "{:04x}".format(ANCOUNT)
    message += "{:04x}".format(NSCOUNT)
    message += "{:04x}".format(ARCOUNT)

    # QNAME is url split up by '.', preceded by int indicating length of part
    addr_parts = address.split(".")
    for part in addr_parts:
        addr_len = "{:02x}".format(len(part))
        addr_part = binascii.hexlify(part.encode())
        message += addr_len
        message += addr_part.decode()

    message += "00"  # Terminating bit for QNAME

    # Type of request
    QTYPE = get_type(type)
    message += QTYPE

    # Class for lookup. 1 is Internet
    QCLASS = 1
    message += "{:04x}".format(QCLASS)

    return message

# Decode the DNS response message and return (response addr, type, query domain_name) tuple


def decode_message(message):
    res = []

    ID = message[0:4]
    query_params = message[4:8]
    QDCOUNT = message[8:12]
    ANCOUNT = message[12:16]
    NSCOUNT = message[16:20]
    ARCOUNT = message[20:24]

    # convert query params to binary 16 bits value
    params = "{:b}".format(int(query_params, 16)).zfill(16)
    QPARAMS = OrderedDict([
        ("QR", params[0:1]),
        ("OPCODE", params[1:5]),
        ("AA", params[5:6]),
        ("TC", params[6:7]),
        ("RD", params[7:8]),
        ("RA", params[8:9]),
        ("Z", params[9:12]),
        ("RCODE", params[12:16])
    ])

    # Question section
    QUESTION_SECTION_STARTS = 24
    question_parts = parse_parts(message, QUESTION_SECTION_STARTS, [])

    QNAME = ".".join(
        map(lambda p: binascii.unhexlify(p).decode(), question_parts))

    QTYPE_STARTS = QUESTION_SECTION_STARTS + \
        (len("".join(question_parts))) + (len(question_parts) * 2) + 2
    QCLASS_STARTS = QTYPE_STARTS + 4

    QTYPE = message[QTYPE_STARTS:QCLASS_STARTS]
    QCLASS = message[QCLASS_STARTS:QCLASS_STARTS + 4]

    res.append("\n# HEADER")
    res.append("ID: " + ID)
    res.append("QUERYPARAMS: ")
    for qp in QPARAMS:
        res.append(" - " + qp + ": " + QPARAMS[qp])
    res.append("\n# QUESTION SECTION")
    res.append("QNAME: " + QNAME)
    res.append("QTYPE: " + QTYPE + " (\"" + get_type(int(QTYPE, 16)) + "\")")
    res.append("QCLASS: " + QCLASS)

    # Answer section
    ANSWER_SECTION_STARTS = QCLASS_STARTS + 4
    answer_found = False
    NUM_ANSWERS = max([int(ANCOUNT, 16), int(NSCOUNT, 16), int(ARCOUNT, 16)])
    if NUM_ANSWERS > 0:
        res.append("\n# ANSWER SECTION")

        for ANSWER_COUNT in range(NUM_ANSWERS):
            if (ANSWER_SECTION_STARTS < len(message)):
                # Refers to Question
                ANAME = message[ANSWER_SECTION_STARTS:ANSWER_SECTION_STARTS + 4]
                ATYPE = message[ANSWER_SECTION_STARTS +
                                4:ANSWER_SECTION_STARTS + 8]
                ACLASS = message[ANSWER_SECTION_STARTS +
                                 8:ANSWER_SECTION_STARTS + 12]
                TTL = int(message[ANSWER_SECTION_STARTS +
                          12:ANSWER_SECTION_STARTS + 20], 16)
                RDLENGTH = int(
                    message[ANSWER_SECTION_STARTS + 20:ANSWER_SECTION_STARTS + 24], 16)
                RDDATA = message[ANSWER_SECTION_STARTS +
                                 24:ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)]

                if ATYPE == get_type("A"):
                    octets = [RDDATA[i:i+2] for i in range(0, len(RDDATA), 2)]
                    RDDATA_decoded = ".".join(
                        list(map(lambda x: str(int(x, 16)), octets)))
                else:
                    parsed_parts_lst = parse_parts(RDDATA, 0, [])
                    parsed_parts_str = ''.join(parsed_parts_lst)
                    if RDLENGTH*2 > (2*len(parsed_parts_lst) + len(parsed_parts_str)//2):
                        unparsed_idx = len(parsed_parts_str) + \
                            2*len(parsed_parts_lst)
                        if str(RDDATA[unparsed_idx:unparsed_idx+2]) == '00':
                            RDDATA_decoded = ".".join(map(lambda p: binascii.unhexlify(
                                p).decode('iso8859-1'), parsed_parts_lst))
                        else:
                            pointer_val = RDDATA[unparsed_idx:unparsed_idx+4]
                            pointer_idx = int(pointer_val[1:], 16)*2
                            parsed_parts_lst = parse_parts(
                                message, pointer_idx, parsed_parts_lst)
                            RDDATA_decoded = ".".join(map(lambda p: binascii.unhexlify(
                                p).decode('iso8859-1'), parsed_parts_lst))
                ANSWER_SECTION_STARTS = ANSWER_SECTION_STARTS + \
                    24 + (RDLENGTH * 2)

            try:
                ATYPE
            except NameError:
                None
            else:
                res.append("# ANSWER " + str(ANSWER_COUNT + 1))
                res.append("QDCOUNT: " + str(int(QDCOUNT, 16)))
                res.append("ANCOUNT: " + str(int(ANCOUNT, 16)))
                res.append("NSCOUNT: " + str(int(NSCOUNT, 16)))
                res.append("ARCOUNT: " + str(int(ARCOUNT, 16)))

                res.append("ANAME: " + ANAME)
                res.append("ATYPE: " + ATYPE +
                           " (\"" + get_type(int(ATYPE, 16)) + "\")")
                res.append("ACLASS: " + ACLASS)

                res.append("\nTTL: " + str(TTL))
                res.append("RDLENGTH: " + str(RDLENGTH))
                res.append("RDDATA: " + RDDATA)
                res.append("RDDATA decoded (result): " + RDDATA_decoded + "\n")
                if answer_found == False:
                    answer = [RDDATA_decoded, ATYPE, QNAME]
                    answer_found = True

    return answer

# get type from saved type list


def get_type(type):
    types = [
        "ERROR",  # type 0 does not exist
        "A",
        "NS",
        "MD",
        "MF",
        "CNAME",
        "SOA",
        "MB",
        "MG",
        "MR",
        "NULL",
        "WKS",
        "PTS",
        "HINFO",
        "MINFO",
        "MX",
        "TXT"
    ]

    return "{:04x}".format(types.index(type)) if isinstance(type, str) else types[type]

# Parse individual parts recursively until termination condition found


def parse_parts(message, start, parts):
    part_start = start + 2
    part_len = message[start:part_start]
    # Incase of compression value(pointer)
    if(str(part_len).lower() == 'c0'):
        return parts
    # if part len is 0, part ends
    if len(part_len) == 0:
        return parts
    part_end = part_start + (int(part_len, 16) * 2)
    parts.append(message[part_start:part_end])
    # QNAME ends with '00'
    if message[part_end:part_end + 2] == "00" or part_end > len(message):
        return parts
    else:
        return parse_parts(message, part_end, parts)

# send the udp message using socket


def send_udp_message(message, address, port):
    message = message.replace(" ", "").replace("\n", "")
    server_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(5)
        sock.sendto(binascii.unhexlify(message), server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return binascii.hexlify(data).decode("utf-8")

# Iteratively send DNS requests and resolve until answer is found for given query_type and url


def iterative_resolve_address(q_type, url):
    q_type = q_type.upper()
    url_split = url.split('.')
    url_len = len(url_split)
    selected_server = random.choice(root_servers)
    for urlPartIndex in range(url_len - 1, -1, -1):
        domain_name = '.'.join(url_split[urlPartIndex:])
        try:
            if urlPartIndex == 0:
                print(
                    f'--> Contacting {socket.gethostbyname(selected_server)} for {q_type} of {domain_name}')
                message = build_message(q_type, url)
                res = send_udp_message(message, selected_server, 53)
                final = decode_message(res)
                if final[1] == '0005':
                    print(f'<-- CNAME of {domain_name} is {final[0]}')
                    selected_server = final[0]
                    if q_type != 'CNAME':
                        iterative_resolve_address(
                        q_type, selected_server)
                else:
                    selected_server = final[0]
                    print(
                        f'<--{q_type} of {domain_name} is {socket.gethostbyname(selected_server)}({selected_server})')
            else:
                if urlPartIndex == url_len - 1:
                    print(
                        f'--> Contacting root ({socket.gethostbyname(selected_server)}) for NS of {domain_name}')
                else:
                    print(
                        f'--> Contacting {socket.gethostbyname(selected_server)} for NS of {domain_name}')
                message = build_message('NS', domain_name)
                res = send_udp_message(message, selected_server, 53)
                final = decode_message(res)
                selected_server = final[0]
                print(
                    f'<-- NS of {domain_name} is {socket.gethostbyname(selected_server)}')
        except IndexError as ie:
            print(f'ERROR <no answer>. Response error, try again!')
            break
        except Exception as e:
            print(f'ERROR <no answer>')
            break

# Entry point of code


def main():
    parser = ArgumentParser(description='Simple iterative DNS resolver')
    parser.add_argument('qtype', type=str,
                        help='Query type (A, NS, MX, CNAME)')
    parser.add_argument('url', type=str, help='URL to resolve')
    args = parser.parse_args()
    iterative_resolve_address(args.qtype, args.url)


if __name__ == '__main__':
    print("Running Iterative_DNSClient.py")
    main()
else:
    print("Imported Iterative_DNSClient.py")
