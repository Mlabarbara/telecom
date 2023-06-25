import socket
import struct

def decode_ipv4_header(binary_string):
    # convert binary string to hexadecimal
    hex_string = '{:0>2x}'.format(int(binary_string, 2))

    # unpack the header fields from the hex string
    version_ihl, tos, tot_len, id, flags_frags, ttl, proto, checksum, src, dest = struct.unpack('!BBHHHBBHII', bytes.fromhex(hex_string))

    # extract version and header length from version_ihl
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F

    # convert protocol number to name
    if proto == 17:
        protocol = "UDP"
    elif proto == 6:
        protocol = "TCP"
    else:
        protocol = str(proto)

    # convert src and dest to dotted decimal format
    src_ip = socket.inet_ntoa(struct.pack('!I', src))
    dest_ip = socket.inet_ntoa(struct.pack('!I', dest))

    # print the decoded header
    print(f"Version: {version}")
    print(f"Header length: {ihl} ({ihl * 4} bytes)")
    print(f"TOS: 0x{tos:02x}")
    print(f"Total Length: 0x{tot_len:04x} ({tot_len} bytes)")
    print(f"Identification: 0x{id:04x}")
    print(f"Flags and Fragments: 0x{flags_frags:04x}")
    print(f"TTL: 0x{ttl:02x} ({ttl} hops)")
    print(f"Protocol: 0x{proto:02x} ({protocol})")
    print(f"Header Checksum: 0x{checksum:04x}")
    print(f"Source: 0x{src:08x} ({src_ip})")
    print(f"Destination: 0x{dest:08x} ({dest_ip})")

#ask the user for the string
binary_string= input("Please enter binary string representing the IPv4 header: ")

#Call the function with user input 
decode_ipv4_header(binary_string)

# test the function with the provided example
#decode_ipv4_header('01000101000000000000000001000100101011010000101100000000000000000100000000010001011100100111001010101100000101000000000010111111011010110000010100000000000000110')
 