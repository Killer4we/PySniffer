import scapy.all as scapy
from scapy.layers import http

class PacketSniffer:
    def __init__(self):
        self.packets = []
        self.sniffing = False

    def start_sniffing(self):
        self.sniffing = True
        self.packets = []
        scapy.sniff(prn=self.process_packet)

    def stop_sniffing(self):
        self.sniffing = False

    def process_packet(self, packet):
        if self.sniffing:
            if packet.haslayer(http.HTTPRequest):
                host = packet[http.HTTPRequest].Host.decode('utf-8')
                path = packet[http.HTTPRequest].Path.decode('utf-8')
                self.packets.append({"host": host, "path": path})

    def extract_features(self):
        return self.packets

