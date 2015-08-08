import binascii

def print_enet_head(dst_mac, src_mac, etype):
    print "Ethernet Header"
    print "--------------------------------"

    dst_mac = binascii.hexlify(dst_mac)
    print "Destination MAC " + (':'.join(dst_mac[i:i+2] for i in range(0,len(dst_mac),2)))

    src_mac = binascii.hexlify(dst_mac)
    print "Source MAC " + (':'.join(dst_mac[i:i+2] for i in range(0,len(dst_mac),2)))

    print "Protocol " + str(hex(etype))
    print "\n",

def print_ip_head(src, dst, proto_num, proto_title):
    print "IP Header"
    print "--------------------------------"

    print "Destination IP " + str(dst)
    print "Source IP " + str(src)
    print "Protocol " + str(proto_num) + " " + proto_title
