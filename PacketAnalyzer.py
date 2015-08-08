#!python/bin/python

import socket
import os
import struct
import pcapy
import binascii

def get_header(pkt):
    fmt = "!6s6sH"
    HEADER_SIZE = 14
    
    print "Ethernet Header"
    print "--------------------------------"
    
    #Destination Address, Source Address, Next Protocol
    (dst_mac, src_mac, etype) = struct.unpack(fmt, pkt[:HEADER_SIZE])

    dst_mac = binascii.hexlify(dst_mac)
    print "Destination MAC " + (':'.join(dst_mac[i:i+2] for i in range(0,len(dst_mac),2)))

    src_mac = binascii.hexlify(dst_mac)
    print "Source MAC " + (':'.join(dst_mac[i:i+2] for i in range(0,len(dst_mac),2)))

    print "Protocol " + str(hex(etype))

    return pkt[HEADER_SIZE:], hex(etype)

def get_IP_header(pkt):
    fmt = "!6H4s4s"
    
    (vit, total_len, id, ffo, ttl_proto, checksum, raw_src, raw_dst) = struct.unpack(fmt, pkt[:20])

    #vit has version, IHL, and TOS
    ver = vit >> 12
    ihl = (vit >> 8) & 0xf
    tos = vit & 0xff

    #ffo has flags and fragment offset
    flags = ffo >> 13
    f_offest = ffo & 0x1fff

    #ttl_proto has ttl and protocol
    ttl = ttl_proto >> 8
    protocol = ttl_proto & 0xff

    #format the src and dst with socket
    src_adr = socket.ntoa(raw_src)
    dst_adr = socket.ntoa(raw_dst)

    if protocol == 6:
        next_proto = "TCP"
    elif protocol == 17:
        next_proto = "UDP"

    return pkt[20:], next_proto

def get_tcp_header(pkt):
    fmt="!2H2I4H"
    (src_port, dst_port, seq, ack, d_off_res, window, chk_sum, urg_ptr) = struct.unpack(fmt, pkt[:20])

    #d_off_res holds data offset, reserved and control bits
    data_off = d_off_res >> 12
    reserved = (d_off_res >> 6) & 0x3f
    ctrl_bits = d_off_res & 0x3f

def get_udp_header(pkt):
    fmt="!4H"
    (src_port, dst_port, length, chk_sum) = struct.unpack(fmt, pkt)

def main():
    #os.system("clear")
    intf = raw_input("Choose a network interface: ")
    sniff = pcapy.open_live(intf, 2048, 1, 0)
    (_,pkt) = sniff.next()
    pkt, etype = get_header(pkt)
    if etype is not 0x800:
        return

    pkt, next_proto = get_IP_header(pkt)

    if next_proto == "TCP":
        get_tcp_header(pkt)
    elif next_proto == "UDP":
        get_udp_header(pkt)
    else:
        return

main()
