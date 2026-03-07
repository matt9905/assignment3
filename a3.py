import struct
import sys

import packet_struct


ETHERNET_HEADER_SIZE = 14
IP_MIN_HEADER_SIZE = 20



COMBINED_IP_AND_ETHERNET_MIN_SIZE = ETHERNET_HEADER_SIZE + IP_MIN_HEADER_SIZE

PROTOCOL_OFFSET_IN_IP_HEADER = 9
    
    
    
    
class Connection:
    
    
    def __init__(self, key):
        self.key = key
        self.lo_packets = []
        
        
        
        self.end_time = 0.0
        
        self.duration = 0.0
        
        self.complete = False
        
        self.start_time = 0.0
        
        
        
        
        
        
        
        self.num_of_rsts = 0
        
        
        self.num_of_syns = 0
        self.num_of_fins = 0
        
        self.status = [0, 0] 
        

        
        self.src_to_dst_packets = 0
        
        self.dst_to_src_packets = 0
        
        self.src_to_dst_bytes = 0
        
        self.dst_to_src_bytes = 0
        
        self.window_sizes = []
        
        self.rtts = []
        
        
        
        
    def append_packet(self, packet):
        self.lo_packets.append(packet)





    def check_and_increment_flags(self):
        
        for p in self.lo_packets:
            
            
            
            
            
            if p.TCP_header.flags.get("SYN") == 1:
                
                
                if self.num_of_syns == 0: #if its the first syn seen
                    self.start_time = p.timestamp
                    
                self.num_of_syns += 1
                    
            
            
            if p.TCP_header.flags.get("FIN") == 1:
                self.num_of_fins += 1
                
                self.end_time = p.timestamp #we update end time each time, so it will be the last fin
    
    
            if p.TCP_header.flags.get("RST") == 1:
                
                
                self.num_of_rsts += 1
                
                
    

    def check_for_complete(self):
        
        
        self.check_and_increment_flags()
                
                
        self.status = [self.num_of_syns, self.num_of_fins]
        
        
        
        
        if self.num_of_fins >=1 and self.num_of_syns >= 1:
            unrounded_duration = self.end_time - self.start_time
            
            self.duration = round(unrounded_duration, 6)
            self.complete = True
            
            
            
    
    



def calculate_connection_details(conn):
        
    
        source_ip = conn.lo_packets[0].IP_header.src_ip
        
        
        if not conn.complete:
            return
        
        
        
        
        
        expected_acks = {}
        
        for p in conn.lo_packets:
            
            
            
            
            payload_size = p.IP_header.total_len - p.IP_header.ip_header_len - p.TCP_header.data_offset
            
            
            
            
            if p.IP_header.src_ip == source_ip:
                conn.src_to_dst_packets += 1
                conn.src_to_dst_bytes += payload_size
            else:
                conn.dst_to_src_packets += 1
                conn.dst_to_src_bytes += payload_size
                
            
            
            
            
            
            
            
            
            
            # the first matching ACK packet
            
            if p.TCP_header.ack_num in expected_acks and p.TCP_header.flags.get("ACK") == 1:
                
                unrounded_computed_rtt = p.timestamp - expected_acks[p.TCP_header.ack_num]
                
                
                rounded_computed_rtt = round(unrounded_computed_rtt, 6)
                
                conn.rtts.append(rounded_computed_rtt)
                
                
                
                del expected_acks[p.TCP_header.ack_num]
                
               
            
        
                    
            if payload_size <= 0 and ( p.TCP_header.flags.get("FIN") == 1 or p.TCP_header.flags.get("SYN") == 1):
                
                cur_calculated_expected_ack = p.TCP_header.seq_num + 1
                if cur_calculated_expected_ack not in expected_acks:
                    expected_acks[cur_calculated_expected_ack] = p.timestamp
                    
            elif payload_size > 0:
                
                cur_calculated_expected_ack = p.TCP_header.seq_num + payload_size
                
                if cur_calculated_expected_ack not in expected_acks:
                    expected_acks[cur_calculated_expected_ack] = p.timestamp
                
            
            conn.window_sizes.append(p.TCP_header.window_size)
                    
                    
                
                
                

        
def parse_global_header(filename):
    #f = open ("sample-capture-file.cap", "rb")
    
    f = open (filename, "rb")
    global_header = f.read(24)
    magic_num, version_major, version_minor, thiszone, sigfigs, snaplen, network = \
        struct.unpack('<IHHIIII', global_header) # little-endian
        
        
    if magic_num == 0xd4c3b2a1:
        #change to big endian mode
        magic_num, version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack(">IHHIIII", global_header)
        endian = '>'
    elif magic_num == 0xa1b2c3d4:
        endian = '<'
    else:
        print("Error: invalid magic number")
        sys.exit(1)
        
        
    return endian, f
    
    
    
    
def parse_packet_header_and_body (endian_format, given_file):
    
    num_packets = 0
    
    packets_tcp = []
    
    time_zero = None
    
    
    # "IIII" is four 4-byte unsigned ints, for a total of 16 bytes
    header_format = endian_format + 'IIII'
    
    packet_header = given_file.read(16)
    
    
    while len(packet_header) == 16:
        
        num_packets += 1
        
        #raw byte slices for the packet_struct.py file
        ts_sec_raw_bytes = packet_header[0:4]
        ts_usec_raw_bytes = packet_header[4:8]
        
        
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(header_format, packet_header)
        
        
        #absolute time = ts_sec + (ts_usec * 10^-6)
        abs_time = ts_sec + (ts_usec * 0.000001)
        
        if time_zero == None:
            time_zero = abs_time
            
            
        
        packet_payload = given_file.read(incl_len)
        
        
        
        
        
        
    
    
        packet_tcp = process_tcp(packet_payload, num_packets, ts_sec_raw_bytes, ts_usec_raw_bytes, time_zero)
        
        if packet_tcp is not None:
            packets_tcp.append(packet_tcp)
        
        
        packet_header = given_file.read(16)
        
        
    return packets_tcp
    
    
    
    
def check_for_completeness(dict_of_connections):
    
    
    lo_conn_tuples = dict_of_connections.items()
    
    
    verified_complete_connections = []
    
    
    
    
    
    for cur_key, cur_connection in lo_conn_tuples:
        
        cur_connection.check_for_complete()
        
        if cur_connection.complete:
            verified_complete_connections.append(cur_connection)
            
            
    return verified_complete_connections
        
        
        
        
        
        
        
        
    
    
    
def process_tcp(packet_payload, num_packets, ts_sec_raw_bytes, ts_usec_raw_bytes, time_zero):
    
    
    
    if len(packet_payload) < COMBINED_IP_AND_ETHERNET_MIN_SIZE:
        return None
    
    
    protocol_offset = PROTOCOL_OFFSET_IN_IP_HEADER + ETHERNET_HEADER_SIZE
    
    protocol_of_given_packet = struct.unpack('B', packet_payload[protocol_offset : protocol_offset+1])[0]
    
    
    # now, check if it's tcp
    
    if protocol_of_given_packet != 6:
        # it is NOT tcp, so return None
        return None
    
    
    # if we make it here, the packet IS tcp!
    
    
    
    
    
    
    
    return create_packet_struct(num_packets, ts_sec_raw_bytes, ts_usec_raw_bytes,time_zero,packet_payload)
        

    

def group_into_connections(packets_tcp):
    
    
    
    dict_of_connections = {}
    
    
    for p in packets_tcp:
        
        cur_src_ip = p.IP_header.src_ip
        cur_dst_ip = p.IP_header.dst_ip
        cur_src_port = p.TCP_header.src_port
        cur_dst_port = p.TCP_header.dst_port
        
        
        # if the dst ip is smaller we want it to come first
        if cur_src_ip > cur_dst_ip:
            smallest_ip = cur_dst_ip
            smallest_port = cur_dst_port
            largest_ip = cur_src_ip
            largest_port = cur_src_port
        else:
            smallest_ip = cur_src_ip
            smallest_port = cur_src_port
            largest_ip = cur_dst_ip
            largest_port = cur_dst_port
            
        cur_key = (smallest_ip, smallest_port, largest_ip,largest_port)
        
        
        
        
        if cur_key not in dict_of_connections:
            dict_of_connections[cur_key] = Connection(cur_key)
            
            
            
        dict_of_connections[cur_key].append_packet(p)
        
        
    return dict_of_connections
        
        
            
        
            
        
            
        
    
    
def create_packet_struct (num_packets, ts_sec_raw_bytes, ts_usec_raw_bytes, time_zero, packet_payload):
    
    
    p = packet_struct.packet()
    
    p.packet_No_set(num_packets)
    
    
    p.timestamp_set(ts_sec_raw_bytes, ts_usec_raw_bytes, time_zero)
    
    
    
    
    ip_header_start_location = ETHERNET_HEADER_SIZE # skip the ethernet header to go straight to ip header
    
    p.IP_header.get_header_len(packet_payload[ip_header_start_location: ip_header_start_location + 1])
    ip_header_len = p.IP_header.ip_header_len
    
    
    
    p.IP_header.get_total_len(packet_payload[ip_header_start_location+2:ip_header_start_location+4])
    
    
    # source ip starts 12 bytes into the ip header
    source_ip_offset = ip_header_start_location + 12
    
    buff1 = packet_payload[source_ip_offset:source_ip_offset + 4]
    
    
    
    # dest ip starts 16 bytes into the ip header
    dest_ip_offset = ip_header_start_location + 16
    buff2 = packet_payload[dest_ip_offset: dest_ip_offset + 4]
    
    
    p.IP_header.get_IP(buff1, buff2)
    
    
    
    tcp_header_start_location = ip_header_start_location + ip_header_len
    
    
    
    
    
    # if the packet is not long enough to have a TCP header then return None
    if len(packet_payload) < tcp_header_start_location + 20:
        return None
    
    
    
    
    return get_values_for_packet(p, packet_payload, tcp_header_start_location)





def get_values_for_packet (pckt, packet_payload, tcp_hdr_start):
    
    pckt.TCP_header.get_src_port(packet_payload[tcp_hdr_start: tcp_hdr_start + 2])
    
    
    
    
    pckt.TCP_header.get_dst_port(packet_payload[tcp_hdr_start+2: tcp_hdr_start + 4])
    
    
    
    pckt.TCP_header.get_seq_num(packet_payload[tcp_hdr_start+4: tcp_hdr_start + 8])
    
    
    pckt.TCP_header.get_ack_num(packet_payload[tcp_hdr_start+8: tcp_hdr_start + 12])
    
    
    pckt.TCP_header.get_data_offset(packet_payload[tcp_hdr_start+12: tcp_hdr_start + 13])
    
    
    pckt.TCP_header.get_flags(packet_payload[tcp_hdr_start+13: tcp_hdr_start + 14])
    
    
    
    
    
    pckt.TCP_header.get_window_size(packet_payload[tcp_hdr_start + 14: tcp_hdr_start+15], packet_payload[tcp_hdr_start + 15: tcp_hdr_start+16])
    
    
    return pckt
    
    



def main(filename):
    endian, file_obj = parse_global_header(filename)
    
    
        
    parsed_tcp_packets = parse_packet_header_and_body(endian, file_obj)
    
    dict_of_connections = group_into_connections(parsed_tcp_packets)
    
    
    returned_complete_conn = check_for_completeness(dict_of_connections)
    
    
    
    for conn in returned_complete_conn:
        
        calculate_connection_details(conn)
    
    
    
    
    
    print("A) Total number of connections: " + str(len(dict_of_connections)))
    
    
    print("")
    
    
    
    
    """
    
    
    self.src_to_dst_packets = 0
    
    self.dst_to_src_packets = 0
    
    self.src_to_dst_bytes = 0
    
    self.dst_to_src_bytes = 0
    
    self.window_sizes = []
    
    self.rtts = []
    
    
    """
    
    print("B) Connections' details:\n")
    
    conn_num = 1
    
    lo_durations = []
    min_time_duration = None
    max_time_duration = None
    
    
    lo_all_rtts = []
    min_rtt = None
    max_rtt = None
    
    
    
    
    lo_total_num_packets = []
    
    min_num_total_packets = None
    
    max_num_total_packets = None
    
    
    
    lo_all_window_sizes = []
    min_window_size = None
    max_window_size = None
    
    
    num_reset_conns = 0
    
    num_open_conns = 0
    
    num_conns_started_before_capture = 0
    
    
    
    
    
    num_complete_conns = 0
    for k, conn in dict_of_connections.items():
        
        
        if conn.num_of_rsts > 0:
            num_reset_conns += 1
        
        if conn.num_of_syns > 0 and conn.num_of_fins == 0:
            num_open_conns += 1
        
        if conn.num_of_syns == 0:
            num_conns_started_before_capture += 1
        
        
        
        if min_time_duration == None or min_time_duration > conn.duration:
            min_time_duration = conn.duration
            
        if max_time_duration == None or max_time_duration < conn.duration:
            max_time_duration = conn.duration
        
        lo_durations.append(conn.duration)
        
        
        for rtt in conn.rtts:
            
        
            if min_rtt == None or min_rtt > rtt:
                min_rtt = rtt
                
            if max_rtt == None or max_rtt < rtt:
                max_rtt = rtt
            
            lo_all_rtts.append(rtt)
            
            
            
        for window_size in conn.window_sizes:
            
        
            if min_window_size == None or min_window_size > window_size:
                min_window_size = window_size
                
            if max_window_size == None or max_window_size < window_size:
                max_window_size = window_size
            
            lo_all_window_sizes.append(window_size)
            
        
        
        
        if conn.complete:
            num_complete_conns+=1
        
        
        
        num_total_packets = conn.dst_to_src_packets + conn.src_to_dst_packets
        
        
        if min_num_total_packets == None or min_num_total_packets > num_total_packets:
            min_num_total_packets = num_total_packets
            
        if max_num_total_packets == None or max_num_total_packets < num_total_packets:
            max_num_total_packets = num_total_packets
        
        lo_total_num_packets.append(num_total_packets)
        
        
        
        
        
        print("Connection " + str(conn_num))
        
        conn_num+=1
        
        
        print("Source Address: " + str(k[2]))
        
        print("Destination Address: " + str(k[0]))
        
        print("Source Port: " + str(k[3]))
        
        print("Destination Port: " + str(k[1]))
        
        
        print("Status: S" + str(conn.status[0]) + "F" + str(conn.status[1]))
        
        
        #complete connection info:
            
        if conn.complete:
            
        
            print("Start Time: " + str(conn.start_time))
            
            print("End Time: " + str(conn.end_time))
            
            print("Duration: " + str(conn.duration))
            
            
            print("Number of packets sent from Source to Destination: " \
                  + str(conn.src_to_dst_packets))
                
                
            print("Number of packets sent from Destination to Source: " \
                  + str(conn.dst_to_src_packets))
               
                
            print("Total number of packets : " \
                  + str(conn.dst_to_src_packets + conn.src_to_dst_packets))
                
                
                
            print("Number of data bytes sent from Source to Destination: " \
                 + str(conn.src_to_dst_bytes))
               
               
            print("Number of data bytes sent from Destination to Source: " \
                 + str(conn.dst_to_src_bytes))
              
               
            print("Total num of data bytes : " \
                 + str(conn.src_to_dst_bytes + conn.dst_to_src_bytes))
            
        print("END\n")
            
            
        
             
               
        
        
        
    print("C) General\n")
    
    print("The total number of complete TCP connections: " + str(num_complete_conns))
    
    print("The number of reset TCP connections " + str(num_reset_conns))
    
    
    print("The number of tcp connections that were still open when the trace capture ended: " \
          + str(num_open_conns))
    
    
    print("The number of tcp connections established before the capture started: " \
          + str(num_conns_started_before_capture))
        
        
    print("")
        
        
        
    print("D) Complete TCP Connections:\n")
    
    print("Minimum time duration: " + str(min_time_duration))
    
    if lo_durations == []:
        print("Mean time duration: " + "None") 
    else:
        
        print("Mean time duration: " + str(sum(lo_durations) / len(lo_durations)))
        
        
        
    print("Maximum time duration: " + str(max_time_duration)) 
    
    
    
    
    print("")
    
    
    """
    
    lo_all_rtts = []
    min_rtt = None
    max_rtt = None
    
    
    """
    
    
    print("Minimum RTT value: " + str(min_rtt))
    
    
    if lo_all_rtts == []:
        print("Mean RTT value: " + "None") 
    else:
        
        print("Mean RTT value: " + str(sum(lo_all_rtts) / len(lo_all_rtts)))
    
        
    
    print("Max RTT value: " + str(max_rtt))
    
    
    print("")
    
    
    
    
    print("Minimum num total packets: " + str(min_num_total_packets))
    
    
    if lo_total_num_packets == []:
        print("Mean num total packets: " + "None") 
    else:
        
        print("Mean num total packets: " + str(sum(lo_total_num_packets) / len(lo_total_num_packets)))
    
        
    
    print("Max num total packets: " + str(max_num_total_packets))
    
    
    print("")
    
    
    
    
    
    
    print("Minimum window size: " + str(min_window_size))
    
    
    if lo_all_window_sizes == []:
        print("Mean window size: " + "None") 
    else:
        
        print("Mean window size: " + str(sum(lo_all_window_sizes) / len(lo_all_window_sizes)))
    
        
    
    print("Max window size value: " + str(max_window_size))
    
    
    
    
    
    
    
    
        
        
    file_obj.close()
    return 0
    




if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        print("Usage: python a3.py <capture_file>")
        sys.exit(1)

    filename = sys.argv[1]
    main(filename)
    
