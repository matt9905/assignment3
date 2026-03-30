import struct
import sys
import packet_struct


def parse_global_header(filename):
    #f = open ("group1-trace1.pcap", "rb")
        
    uses_nano = True
    
    f = open (filename, "rb")
    global_header = f.read(24)
    magic_num, version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack('<IHHIIII', global_header) # little-endian
        
    
        
    if magic_num == 0xd4c3b2a1: #3569595041
        #change to big endian mode
        endian = '>'
        uses_nano = False
    elif magic_num == 0xa1b2c3d4: # 2712847316 #2712812621 
        endian = '<'
        uses_nano = False
    elif magic_num == 0xA1B23C4D : 
        #microsecond precision, big endian
        endian = '<'
        
        
    elif magic_num == 0x4d3cb2a1:
        #microsecond precision, little endian
        endian = '>'
    else:
        print("Error: invalid magic number")
        print("magic number is: " + str(magic_num))
        sys.exit(1)
        
        
    return endian, f, uses_nano




    
def parse_packet_header_and_body (endian_format, given_file, uses_nano):
    
    
    
    
    if uses_nano:
        timestamp_multiplier = 0.000000001
    else:
        timestamp_multiplier = 0.000001
        
        
        
    num_packets = 0
    
    packets = []
    
    time_zero = None
    
    
    # "IIII" is four 4-byte unsigned ints, for a total of 16 bytes
    header_format = endian_format + 'IIII'
    
    packet_header = given_file.read(16)
    
    #print("header format is " + str(header_format))
    
    
    while len(packet_header) >= 16:
        
        num_packets += 1

        #print("iteration!!")
        #raw byte slices for the packet_struct.py file
        ts_sec_raw_bytes = packet_header[0:4]
        ts_subsec_raw_bytes = packet_header[4:8]
        
        
        ts_sec, ts_subsec, incl_len, time_zero = struct.unpack(header_format, packet_header)
        
        #print("incl_len is " + str(incl_len))
        
        #absolute time = ts_sec + (ts_subsec * 10^-6)
        abs_time = ts_sec + (ts_subsec * timestamp_multiplier)
        
        if time_zero == None:
            time_zero = abs_time
        packet_payload = given_file.read(incl_len)
        
            
            
        parsed = process_traceroute_pckt(packet_payload, num_packets, ts_sec_raw_bytes, ts_subsec_raw_bytes, time_zero)
        
        #print(packet_payload.decode('utf-8', 'ignore'))
        
        if parsed is not None:
            parsed.timestamp = abs_time
            packets.append(parsed)
        
        
    
        
        
        packet_header = given_file.read(16)
        
        
    return packets
    
    
    
def process_traceroute_pckt(packet_payload, num_packets, ts_sec_raw_bytes, ts_usec_raw_bytes, time_zero):
    
    
    
    if len(packet_payload) < 34:
        return None
    
    type_and_ihl = struct.unpack('>H',  packet_payload[12:14])
    
    eth_type = type_and_ihl[0]

    
    if eth_type != 0x0800: # 0x0800 signifies ipv4
        return None
    
    
    
    cur_packet = packet_struct.packet()
    cur_packet.packet_No_set(num_packets)
    
    cur_packet.timestamp_set(ts_sec_raw_bytes, ts_usec_raw_bytes, time_zero)
    
    
    
    cur_packet.IP_header.get_header_len(packet_payload[14: 15]) # 14 means ip start
    ip_length = cur_packet.IP_header.ip_header_len
    
    
    cur_packet.IP_header.get_IP(
        packet_payload[26: 30],
        packet_payload[30: 34]
    )
    
    
    cur_packet.IP_header.get_protocol(packet_payload[23: 24])
    cur_packet.IP_header.get_fragmentation_info(packet_payload[18:20], packet_payload[20:22])
    
    cur_protocol = cur_packet.IP_header.protocol
    
    if cur_protocol != 1 and cur_protocol != 17:
        return None
    


    payload_start = 14 + ip_length # ip start is 14
    
    udp_condition = payload_start + 4
    
    icmp_condition = payload_start + 8
    
    
    
    
    if payload_start + 4 <= len(packet_payload) and cur_protocol == 17:
        cur_packet.UDP_header = packet_struct.UDP_Header()
        cur_packet.UDP_header.get_ports(packet_payload[payload_start: payload_start + 4])

        if 33434 <= cur_packet.UDP_header.dst_port <= 33529:
            cur_packet.probe = True # 10 : 21

    elif payload_start + 8 <= len(packet_payload) and cur_protocol == 1:
        cur_packet.ICMP_header = packet_struct.ICMP_Header()
        cur_packet.ICMP_header.get_type_and_code(packet_payload[payload_start: payload_start + 2])


        icmp_type = cur_packet.ICMP_header.type


        if icmp_type == 8:
            cur_packet.probe = True
            cur_packet.ICMP_header.get_sequence_num(packet_payload[payload_start + 6: payload_start + 8])

        elif icmp_type == 11 or icmp_type == 0:
            cur_packet.err = True
            og_ip_start = payload_start + 8



            if og_ip_start + 20 <= len(packet_payload):
                og_ihl = 4 * (packet_payload[og_ip_start] & 0x0F)
                og_protocol = packet_payload[og_ip_start + 9]
                og_payload_start = og_ip_start + og_ihl



                format_str = '>H'
                if og_protocol == 17 and len(packet_payload) >= og_payload_start + 2:
                    cur_packet.embedded_match_key = \
                    struct.unpack(format_str, packet_payload[og_payload_start: og_payload_start + 2])[0]
                elif og_protocol == 1 and len(packet_payload) >= og_payload_start + 8:
                    
                    cur_packet.embedded_match_key = \
                    struct.unpack(format_str, packet_payload[og_payload_start + 6: og_payload_start + 8])[0]
                
            if icmp_type == 0 and not cur_packet.embedded_match_key:
                cur_packet.embedded_match_key = \
                struct.unpack(format_str, packet_payload[payload_start + 6: payload_start + 8])[0]
    
    return cur_packet


def analyze_traceroute(packets):
    frags_dict = {}
    frag_count = 0
    
    last_frag_offset = 0

    probes_sent =  {}
    rtt_measurements = {}

    src_node = None
    final_dest = None

    lo_intermediate_nodes = []
    
    lo_ult_rtts = []

    protocols = []



    index_num = 1

    prev_id_num = -1
    prev_offset_num = -1

    occurences_of_ttl_exceeded = 0

    for p in packets:
        # check if p.ICMP_header.type == 3000 only one time for all fragments with the same id
        # if so, you need to 
        if p.IP_header.identification not in frags_dict:
                # this means its a new fragment
                occurences_of_ttl_exceeded = 0
                frags_dict[p.IP_header.identification] = [None, None, None] #index, offset, error_timestamp
        
        if p.ICMP_header is not None and p.ICMP_header.type == 3000:
            occurences_of_ttl_exceeded += 1
            frags_dict[p.IP_header.identification][2] = p.timestamp
            p.err = True
        
        if occurences_of_ttl_exceeded >= 2:
            p.calculate_rtt_differently = True
        if prev_offset_num < 0:
            prev_offset_num = p.IP_header.frag_offset
        
        
        if prev_id_num < 0:
            # first packet
            prev_id_num = p.IP_header.identification
            
        else:
            if prev_id_num == p.IP_header.identification:
                #if the past packet id num is the same as the current one:
                index_num += 1
            else:
                

                #print("The number of fragments created from the original datagram " + str(prev_id_num) + " is :" + str(index_num))
                index_num = 1
                #print("The offset of the last fragment is: " + str(prev_offset_num))
                
                

                
            prev_id_num = p.IP_header.identification
            prev_offset_num = p.IP_header.frag_offset
        frags_dict[p.IP_header.identification][0] = index_num
        frags_dict[p.IP_header.identification][1] = prev_offset_num
        frags_dict[p.IP_header.identification][2] = p.timestamp

    for p in packets:
        #print("Fragment number " + str(index_num), end= "")
                
        
        
        #print("    ID: " + str(p.IP_header.identification))
        
        #print("frag count = " + str(frag_count))

        if p.IP_header.protocol not in protocols:

            protocols.append(p.IP_header.protocol)
        if src_node is None:
            src_node = p.IP_header.src_ip


            # this below if block should be moved back
        if p.probe and p.IP_header.src_ip == src_node:
            
            final_dest = p.IP_header.dst_ip

            cur_offset = p.IP_header.frag_offset

            
            if p.IP_header.flags == 1 or cur_offset > 0:
                if last_frag_offset < cur_offset:
                    last_frag_offset = cur_offset
                if cur_offset == 0:
                    frag_count = 0
                frag_count += 1
            elif frag_count == 0:
                frag_count = 1


            if p.IP_header.protocol == 17:
                match_key = p.UDP_header.src_port
            else:
                match_key = p.ICMP_header.seq_num
            if match_key not in probes_sent:
                probes_sent[match_key] = []
            probes_sent[match_key].append(p.timestamp)
        elif p.IP_header.dst_ip == src_node and p.err:
            router_ip = p.IP_header.src_ip

            if router_ip != final_dest and router_ip not in lo_intermediate_nodes:
                lo_intermediate_nodes.append(router_ip)
                rtt_measurements[router_ip] = []

            # if the current ip address is the same as the destination, append it to the ultimate rtt dest
            cur_embedded_match_key = p.embedded_match_key
            
            #print(cur_embedded_match_key )
            

            if cur_embedded_match_key and cur_embedded_match_key in probes_sent:
                
                for t in probes_sent[cur_embedded_match_key]:
                    
                    
                    # RTT = error timestamp - probe timestamp
                    cur_rtt = (p.timestamp - t) * 1000
                    
                    cur_rtt = round(cur_rtt, 6) #CONVERT TO MS, MIGHT BE WRONG MAYBE HAVE TO CHECK NANO VS MICRO
                    
                    #print("cur_rtt= " + str(cur_rtt))
                    #print("router_ip= " + str(router_ip))
                    #print("final_dest= " + str(final_dest))
    
                    if router_ip != final_dest:
                        rtt_measurements[router_ip].append(cur_rtt)
                    else:
                        lo_ult_rtts.append(cur_rtt)
                        pass #implement solution where at the end of for loop we add the ultimate rtt

                del probes_sent[cur_embedded_match_key]


    # if the datagram is not fragmented, the offset is 0.
    # if there is only one fragment (meaning it is not fragmented)
    if last_frag_offset == 0 and frag_count == 1:
        pass #TODO: IMPLEMENT MY SOLUTION HERE! 

            # Enforce the unfragmented rule specifciation from Q&A pdf
            #  The pdf expects *1* and *0 bytes* for unfragmented traces

    return src_node, final_dest, lo_intermediate_nodes, protocols, frag_count, last_frag_offset, rtt_measurements, lo_ult_rtts, frags_dict








def output_answers(src_node, dest_node, lo_intermediate_nodes, protocols, frag_count, last_frag_offset, rtt_measurements, lo_ult_rtts, frags_dict):

    print("The IP address of the source node: " + str(src_node))

    
    print("The IP address of ultimate destination node: " + str(dest_node))
    

    print("The IP addresses of the intermediate destination nodes:")
    index = 1
    nodelistlength = len(lo_intermediate_nodes)
    for r in lo_intermediate_nodes:
        print("        router " + str(index) + ": " + str(r), end="")
        print(".") if index==nodelistlength else print(",")
        index += 1
    
    
    print("\nThe values in the protocol field of IP headers:")

    sorted_prots = sorted(protocols)

    for prot in sorted_prots:
        if prot==1:
            print("        1: ICMP")
        if prot==17:
            print("        17: UDP")


    for id, num_and_offset_list in frags_dict.items():
        cur_num = num_and_offset_list[0]
        cur_offset = num_and_offset_list[1]

        print("\nThe number of fragments created from the original datagram " + str(id) + " is: " + str(cur_num))

        print("\nThe offset of the last fragment is: " + str(cur_offset) + " bytes\n")
        



    for r in lo_intermediate_nodes:
        #print("R = " + str (r))
        #print("PASSED LIST = " + str(rtt_measurements[r]))
        # current issue: compute data gets passed a list of ip addresses instead of a list of round trip times.
        cur_mean_rtt, cur_sd_rtt = compute_data(rtt_measurements[r])

        if cur_mean_rtt.is_integer():
            cur_mean_rtt = int(cur_mean_rtt)

        if cur_sd_rtt.is_integer():
            cur_sd_rtt = int(cur_sd_rtt)

        print("The avg RTT between " + str(src_node) + " and " + str(r) + " is: " \
               + str(cur_mean_rtt) + " ms, the s.d. is: " + str(cur_sd_rtt) + " ms")
        
        

    # 00:20:30
    #print(lo_ult_rtts)
    if lo_ult_rtts != []:
        
        cur_mean_ult_rtt, cur_sd_ult_rtt = compute_data(lo_ult_rtts)
            

        if cur_mean_ult_rtt.is_integer():
            cur_mean_ult_rtt = int(cur_mean_ult_rtt)

        if cur_sd_ult_rtt.is_integer():
            cur_sd_ult_rtt = int(cur_sd_ult_rtt)
        
        print("The avg RTT between " + str(src_node) + " and " + str(r) + " is: " \
               + str(cur_mean_ult_rtt) + " ms, the s.d. is: " + str(cur_sd_ult_rtt) + " ms")
    



        
def compute_data(lo_rtts):
    #print("LO_RTTS = " + str(lo_rtts))
    mean_rtt, variance = 0.0, 0.0
    if lo_rtts!=[]:
        sum = 0.0
        variance = 0.0
        for element in lo_rtts:
            
            sum += element
            
        
        mean_rtt = sum / len(lo_rtts)
        if len(lo_rtts) > 1:
            sum2=0
            for element in lo_rtts:
                sum2 += (element - mean_rtt) ** 2

            variance = sum2/(len(lo_rtts) - 1)
        
    
    

    return round(mean_rtt, 2), round((variance) ** .5, 2)
    





  


if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        print("Usage: python a3.py <capture_file>")
        sys.exit(1)

    filename = sys.argv[1]
    #main(filename)

    endian, file_obj, uses_nano = parse_global_header(filename)
    
    #print("endian is: " + str(endian))
    
    
    packets = parse_packet_header_and_body(endian, file_obj, uses_nano)
    

    
    

    src_node, dest_node, lo_intermediate_nodes, protocols, frag_count, last_frag_offset, rtt_measurements, lo_ult_rtts, frags_dict = analyze_traceroute(packets)

    output_answers(src_node, dest_node, lo_intermediate_nodes, protocols, frag_count, last_frag_offset, rtt_measurements, lo_ult_rtts, frags_dict)



    file_obj.close()

    
    

    
    
    
    
    