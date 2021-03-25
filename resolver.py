from os import name
import sys
import socket
from struct import *
import random


def stringToNetwork(orig_string):
    """
    Converts a standard string to a string that can be sent over
    the network.

    Args:
        orig_string (string): the string to convert

    Returns:
        bytes: The network formatted string (as bytes)

    Example:
        stringToNetwork('www.sandiego.edu.edu') will return
          (3)www(8)sandiego(3)edu(0)
    """
    ls = orig_string.split('.')
    toReturn = b""
    for item in ls:
        formatString = "B"
        formatString += str(len(item))
        formatString += "s"
        toReturn += pack(formatString, len(item), item.encode())
    toReturn += pack("B", 0)
    return toReturn


def networkToString(response, start):
    """
    Converts a network response string into a human readable string.

    Args:
        response (string): the entire network response message
        start (int): the location within the message where the network string
            starts.

    Returns:
        A (string, int) tuple
            - string: The human readable string.
            - int: The index one past the end of the string, i.e. the starting
              index of the value immediately after the string.

    Example:  networkToString('(3)www(8)sandiego(3)edu(0)', 0) would return
              ('www.sandiego.edu', 18)
    """

    toReturn = ""
    position = start
    length = -1
    while True:
        length = unpack("!B", response[position:position+1])[0]
        if length == 0:
            position += 1
            break

        # Handle DNS pointers (!!)
        elif (length & 1 << 7) and (length & 1 << 6):
            b2 = unpack("!B", response[position+1:position+2])[0]
            offset = 0
            """
            # strip off leading two bits shift by 8 to account for "length"
            # being the most significant byte
            ooffset += (length & 1 << i)ffset += (length & 0x3F) << 8  

            offset += b2
            """
            for i in range(6) :
                offset += (length & 1 << i) << 8
            for i in range(8):
                offset += (b2 & 1 << i)
            dereferenced = networkToString(response, offset)[0]
            return toReturn + dereferenced, position + 2

        formatString = str(length) + "s"
        position += 1
        toReturn += unpack(formatString, response[position:position+length])[0].decode()
        toReturn += "."
        position += length
    return toReturn[:-1], position


def constructQuery(ID, hostname, input_qtype = 1):
    """
    Constructs a DNS query message for a given hostname and ID.

    Args:
        ID (int): ID # for the message
        hostname (string): What we're asking for

    Returns:
        string: "Packed" string containing a valid DNS query message
    """
    flags = 0 # 0 implies basic iterative query

    # one question, no answers for basic query
    num_questions = 1
    num_answers = 0
    num_auth = 0
    num_other = 0

    # "!HHHHHH" means pack 6 Half integers (i.e. 16-bit values) into a single
    # string, with data placed in network order (!)
    header = pack("!HHHHHH", ID, flags, num_questions, num_answers, num_auth,
                  num_other)

    qname = stringToNetwork(hostname)
    qtype = input_qtype
    remainder = pack("!HH", qtype, 1)
    query = header + qname + remainder
    return query


def resolve(hostname, is_mx=False, input_IP=None):
    """
    Returns a string with the IP address (for an A record) or name of mail
    server associated with the given hostname.

    Args:
        hostname (string): The name of the host to resolve.
        is_mx (boolean): True if requesting the MX record result, False if
          requesting the A record.

    Returns:
        string: A string representation of an IP address (e.g. "192.168.0.1") or
          mail server (e.g. "mail.google.com"). If the request could not be
          resolved, None will be returned.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)   # socket should timeout after 5 seconds

    # Create an (example) query 
    # Note: The ID is just a random number I picked. In your final code, every
    # query should contain a different, randomly generated ID.

    # ID between 1 and 65535
    query_id = random.randint(0,65535)
    
    # If it is an MX request, the query is constructed with the MX type, else, A type
    if (is_mx):
        query = constructQuery(query_id, hostname, 15)
    else:
        query = constructQuery(query_id, hostname)
    
    try:
        # If no new IP to query, re open root servers to start back at root server 1
        if (input_IP == None):
            root_server_file = open("root-servers.txt")
            root_server = root_server_file.readline()
            root_server = root_server.replace("\n", "")
            print("Querying: ", hostname, " at root server: ", root_server)

            # Send query to root server
            sock.sendto(query, (root_server, 53))
        
        else:
            print("Querying: ", hostname, " at IP: ", input_IP)

            # Query next IP 
            sock.sendto(query,(input_IP, 53))

        # Receive the response (timing out after 5 seconds)
        response = sock.recv(4096)

        # TODO: Extract the necessary information from the response to get the
        # answer. You'll want to use the unpack function to get started.
        # (query ID, flags, questions, Answer RR's, Authority RR's, Additiona; RR's
        hostname_length = len(hostname)

        # Unpack the flags (binary) and number of AUTH RR's and ADD RR's
        dns_response = unpack("!HHHHHH", response[:12])
        res_flags = f'{dns_response[1]:016b}' # binary rep
        res_authority_rrs = dns_response[4]
        res_additional_rrs = dns_response[5]

        # Query section: Name (20) Type (2) Class (2)
        query_size = hostname_length + 6

        # Answer(s) Section: Name(2), Type(2), Class(2), TTL(4), Data Length(2), Address(4)
        answer_start = query_size + 12
        ans_unpack = unpack("!HHIH", response[hostname_length+20:hostname_length+30])
        res_answer_type = ans_unpack[0]

        # CASE: SOA flags hit -> Invalid hostname
        if (res_flags[-2:] == "11"):
            print("ERROR: Invalid hostname")
            return None

        # ! Begin Recursive Logic ! 

        # Base Case: If the answer is authoritative and not a CNAME record
        if (res_flags[5] == "1" and res_answer_type != 5):

            # If MX, return name of mail server
            if (is_mx):
                if (res_answer_type == 6):
                    return None
                return networkToString(response, 32+hostname_length)[0]
            
            # Return the final IP
            return get_a_record_ip(response, hostname_length)
        else:
            #CASE: CNAME Record Type
            if (res_answer_type == 5):
                cname_name = networkToString(response, answer_start+12)[0]
                return resolve(cname_name, is_mx)

            # CASE: NS Record Type 
            elif (res_answer_type == 2):

                # Populate lists of Authoritative nameservers and Additional nameservers and IPs
                auth_nameservers, add_nameservers, add_ips = handle_NS_record(response, answer_start, res_authority_rrs, res_additional_rrs)

                # CASE: Authoritative and Additional Records exist
                if (res_authority_rrs > 0 and res_additional_rrs > 0):
                    # Check if Authoritative nameserver matches add nameserver
                    match_index = match(auth_nameservers, add_nameservers)
                    if (match_index != -1):
                        # Match found, query same hostname to new ip
                        return resolve(hostname, is_mx, add_ips[match_index])
                    else:
                        # No match found, query first Authoritative nameserver to first DNS root server
                        return resolve(auth_nameservers[0], is_mx)
                
                # CASE: Only Authoritative Records exist 
                elif (res_authority_rrs > 0 and res_additional_rrs == 0):
                    # Resolve Authoritative nameserver and recursive resolve original hostname with that new ip
                    returned_ip = resolve(auth_nameservers[0], is_mx)
                    if(returned_ip == None):
                        return None
                    return resolve(hostname, is_mx, returned_ip)
                
                #CASE: Only Additional Records exist (Really should never happen)
                elif (res_authority_rrs == 0 and res_additional_rrs > 0):
                    # Make sure only records aren't type AAAA
                    if (add_ips[0] != 0):
                        return resolve(hostname, is_mx, add_ips[0])
                    else:
                        print("ERROR: No Authority RR's and only Additional RR is Type: AAAA")
                        return None
                else:
                    #CASE: No Authoritative Records and No Additional Records in NS Record
                    print("ERROR: NS Response with no Authority RR's and no Additional RR's")
                    return None

    # Socket timed out (Try next root server)
    except socket.timeout as e:
        print("Exception:", e)
        return resolve(hostname, is_mx, None)

    return None

def match(auth_nameservers, add_nameservers):
    """
    Checks is there is a match of nameservers in Authoritative and Additional. If there is, 
    it returns the index of that match. If not, it returns -1. 

    Args:
        auth_nameservers(list): List of nameservers from the Authoritative Records
        add_name_servers(list): List of nameservers from the Additional Records

    Returns:
        int: Index of match if a match was found. Else, -1
    """
    for i in range(len(auth_nameservers)):
        for j in range(len(add_nameservers)):
            if (auth_nameservers[i] == add_nameservers[j]):
                return j
    return -1

def get_a_record_ip(response, hostname_length):
    """
    Returns the IP address of the final response. 

    Args:
        response(bytes): Bytes containing the DNS response
        hostname_length(int): Length of the requested hostname

    Returns:
        string: A string representation of the resulting IP address
    """
    ans_unpack = unpack("!HHIHI", response[hostname_length+20:hostname_length+34])
    res_answer_ip = socket.inet_ntoa(pack("!I", ans_unpack[4]))
    return res_answer_ip

def handle_NS_record(response, answer_start, auth_records, add_records):
    """
    Loops through the DNS response in order to populate lists to hold nameservers and IPs

    Args:
        response(bytes): Bytes containing the DNS response
        answer_start(int): Index of where the response answer starts in the response
        auth_records(int): Number of Authoritative Records
        add_records (int): Number of Additional Records

    Returns:
        nameservers(list): List containing the names of the servers in the Authoritative Responses
        add_nameservers(list): List containing the names of the servers in the Additional Responses
        nameserverIP(list): List containing the IPs of the respective servers in Additional Responses
    """
    nameservers = []
    add_nameservers = []
    nameserverIP = []
    next_start = answer_start

    # Adds all nameservers in Authoritative Records to nameservers
    for i in range(auth_records):
        name_server = networkToString(response, next_start + 12)
        next_start = name_server[1]
        nameservers.append(name_server[0])
    
    # Adds all nameservers and IPs in Additional Records to nameserverIP and add_nameservers respectively
    add_start = next_start
    if add_records > 0:
        # i index ensures nameservers and IPs are added in the same order
        for i in range(add_records):
            record_type = unpack("!H", response[add_start+2:add_start+4])[0]
            if record_type == 1:
                name_server = networkToString(response, add_start)
                temp_IP = unpack("!I", response[add_start+12:add_start+16])[0]
                name_server_IP = socket.inet_ntoa(pack("!I", temp_IP))
                add_nameservers.append(name_server[0])
                nameserverIP.append(name_server_IP)
                add_start = add_start + 16
            else:
                add_nameservers.append(0)
                nameserverIP.append(0)
                add_start = add_start + 28

    return nameservers, add_nameservers, nameserverIP

def main(argv):
    """
    Main function to facilitate command line usage. 

    Args:
        argv(list): list of command line inputs
    """
    if (argv[1] != "-m"):
        answer = resolve(argv[1], False)
    else:
        answer = resolve(argv[2], True)

    if answer is not None:
        print(f"Answer: {answer}")
    else:
        print("Could not resolve request.")

if __name__ == "__main__":
    main(sys.argv)
