import pyshark
from flowdiagram import flowdiagram
import json


class PcapPython:

    def __init__(self, file_path, only_summaries):
        self.file_path = file_path
        self.only_summaries = only_summaries
        capture = pyshark.FileCapture(file_path, only_summaries)
        self.packets = [packet for packet in capture]

    def number_of_packets(self):
        return len(self.packets)

    def filter_by_protocol(self, protocol):
        self.packets = [
            packet for packet in self.packets if packet.highest_layer == protocol]
        # return [packet for packet in self.packets if packet.highest_layer == protocol]
        # return "Packets filtered by -> {}".format(protocol)

    def filter_by_protocols(self, *protocols):
        self.packets = [
            packet for packet in self.packets if packet.highest_layer in protocols]

    def get_eth_info(self, packet):
        frame = packet.frame_info._all_fields
        # DICTIONARY (Exact field:values are in comment below for reference)
        return frame
        # {'frame.encap_type': '25',
        # 'frame.time': 'Sep  5, 2022 17:16:45.737352000 India Standard Tndard Time',
        # 'frame.offset_shift': '0.000000000', 'frame.time_epoch': '1662378405.70',
        # 'fr37352000', 'frame.time_delta': '0.191842000', 'frame.time_delta_displayed': '0.1918.time_r42000',
        # 'frame.time_relative': '0.191842000', 'frame.number': '2', 'frame.len': '10pert In0',
        # '_ws.expert': 'Expert Info (Error/Malformed): Frame length is less than capturelen': 'd length',
        # 'frame.len_lt_caplen': 'Frame length is less than captured length',
        # '_wsless th.expert.message': 'Frame length is less than captured length',
        # '_ws.expert.severity12', 'f': '8388608', '_ws.expert.group': '117440512',
        # 'frame.cap_len': '116', 'frame.marke 'sll:ed': '0', 'frame.ignored': '0',
        # 'frame.protocols': 'sll:ethertype:ip:sctp'}

    def get_ip_info(self, packet):
        ip_packet = packet.ip._all_fields
        # DICTIONARY (Exact field:values are in comment below for reference)
        return ip_packet
    # {'ip.version': '4', 'ip.hdr_len': '20', 'ip.dsfield': '0x02', 'ip.dsfield.dscp': '0',
    # 'ip.dsfield.ecn': '2', 'ip.len': '84', 'ip.id': '0x94b1', 'ip.flags': '0x00',
    # 'ip.flags.rb': '0', 'ip.flags.df': '0', 'ip.flags.mf': '0', 'ip.frag_offset': '0',
    # 'ip.ttl': '64', 'ip.proto': '132', 'ip.checksum': '0x1659', 'ip.checksum.status': '2',
    # 'ip.src': '10.28.13.201', 'ip.addr': '10.28.13.201', 'ip.src_host': '10.28.13.201',
    # 'ip.host': '10.28.13.201', 'ip.dst': '100.97.82.212', 'ip.dst_host': '100.97.82.212'}

    def get_sll_info(self, packet):
        sll_data = packet.sll._all_fields
        return sll_data
    
    def get_sctp_info(self,packet):
        sctp_data= packet.sctp._all_fields
        return sctp_data
    
    def get_s1ap_info(self,packet):
        s1ap_data = packet.s1ap._all_fields
        return s1ap_data

    def params_msg_parser(self, packet):
        # Custom Message
        # Example:
        # IP [v=4 ip_src=192.168.0.1 ip_dst=8.8.8.8 ttl=64 id=0x94b1]
        pr_msg = "Protocol {}".format(packet.highest_layer)
        ip_data = self.get_ip_info(packet)  # Returns a dictionary
        # print(ip_data)
        ip_msg = "IP "
        ip_msg = "IP [v={} src={} dst={} ttl={} ]".format(
            ip_data['ip.version'],
            ip_data['ip.src'],
            ip_data['ip.dst'],
            ip_data['ip.ttl']
        )
        eth_data = self.get_eth_info(packet)
        eth_msg = "ETH [num={} pr={} len={}]".format(
            eth_data['frame.number'],
            eth_data['frame.protocols'],
            eth_data['frame.cap_len']
        )
        msg = pr_msg+"\n"+ip_msg+"\n"+eth_msg+"          "
        return msg
    
    def msg_parser(self,packet):
        codes_file = open('procedure_codes.json')
        chunks_file = open('chunk_types.json')
        codes = json.load(codes_file)
        chunk_types = json.load(chunks_file)
             
        #Getting chunk type from sctp layer
        sctp_data = self.get_sctp_info(packet)
        chunk_code = sctp_data['sctp.chunk_type']
        chunk = chunk_types[chunk_code]
        
            #Getting message information from S1AP layer
        s1ap_data = self.get_s1ap_info(packet)
        # p_code = s1ap_data['s1ap.procedureCode']
        procedure_mode = self.procedureMode(s1ap_data,codes)
        # procedure =  codes[p_code]
        procedure = procedure_mode
        
        #Message string
        msg = "{} ( {} )".format(chunk,procedure)
        codes_file.close()
        chunks_file.close()
        return msg
    
    def procedureMode(self,s1ap_data,codes):
        msg = ""
        p_code = s1ap_data['s1ap.procedureCode']
        
        if p_code == "9":
            # InitialContextSetup code Request or Response
            if "s1ap.InitialContextSetupResponse_element" in s1ap_data:
                print(True)
                msg = s1ap_data["s1ap.InitialContextSetupResponse_element"]
            
            elif "s1ap.InitialContextSetupRequest_element" in s1ap_data:
                msg = s1ap_data["s1ap.InitialContextSetupRequest_element"]
               
        elif p_code == "5":
            # E-RABSetup code Request or Response
            if "s1ap.E_RABSetupResponse_element" in s1ap_data:
                msg = s1ap_data["s1ap.E_RABSetupResponse_element"]
            elif "s1ap.E_RABSetupRequest_element" in s1ap_data:
                msg= s1ap_data["s1ap.E_RABSetupRequest_element"]
                
        elif p_code == "23":
            # UEContextRelease code Command or Complete
            if "s1ap.UEContextReleaseCommand_element" in s1ap_data:
                msg = ["s1ap.UEContextReleaseCommand_element"]
            elif "s1ap.UEContextReleaseComplete_element" in s1ap_data:
                msg = ["s1ap.UEContextReleaseComplete_element"]
            
        else:
            # Others Plain procedures without variation or have different p_codes
            msg = codes[p_code]
        
        return msg

    def createSqd(self, title):
        sqd = flowdiagram()
        sqd.setTitle(title)
        print("Creating IP Flow...")
        file = open('devices.json')
        devices = json.load(file)
        for packet in self.packets:
            # msg = self.params_msg_parser(packet)
            msg = self.msg_parser(packet)
            # print(type(msg))
            if 'IP' in packet:
                src = packet['IP'].src
                dst = packet['IP'].dst
                sqd.addFlow([devices[src], devices[dst], msg])

        sqd.drawPicture()


file = 's2_cicd.pcap'

pcap1 = PcapPython(file, False)
pcap1.filter_by_protocol("S1AP")
# pcap1.filter_by_protocols("SCTP","DATA")
print(pcap1.number_of_packets())
pcap1.createSqd("Test")
