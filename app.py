from flask import Flask, render_template, request
import threading
import time
from packetsniffer import PacketSniffer

app = Flask(__name__)
packet_sniffer = PacketSniffer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sniff', methods=['GET', 'POST'])
def sniff_packets():
    if request.method == 'POST':
        if 'start' in request.form:
            # Start sniffing packets in a separate thread
            sniffer_thread = threading.Thread(target=packet_sniffer.start_sniffing)
            sniffer_thread.start()
        elif 'stop' in request.form:
            # Stop sniffing packets and extract features
            packet_sniffer.stop_sniffing()
            features = packet_sniffer.extract_features()
            return render_template('features.html', features=features)
    return render_template('index.html')

if __name__ == '__main__':
    app.run()

