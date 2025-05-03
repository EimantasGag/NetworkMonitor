from websockets.sync.client import connect
import pyshark
import psutil
import socket

host_interface = 'Ethernet'
host_mac = None

cachedPorts = {} # port -> process name

def get_mac_address(interface_name):
    addrs = psutil.net_if_addrs()
    for addr in addrs.get(interface_name, []):
        if addr.family == psutil.AF_LINK:
            return addr.address
    return None

def get_hostname_by_ip(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "Hostname not found"

def find_pid_by_port(port):
    port = int(port)
    for conn in psutil.net_connections(kind='all'):
        if conn.laddr.port == port:
            if conn.pid is not None:
                return conn.pid
    return None

def find_processname_by_pid(pid):
    if pid is not None:
        try:
            process = psutil.Process(pid)
            return process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    return None

def create_message(packet, type):
    packet_mac = packet.eth.dst
    length = int(packet.frame_info.len)
    
    # Receiving packets
    if packet_mac == host_mac:
        port = int(packet.tcp.dstport) if type == 'tcp' else int(packet.udp.dstport)

        if port not in cachedPorts:
            proc_name = find_processname_by_pid(find_pid_by_port(port))

            # If a packet is received on port 80 or 443, get the hostname by IP
            if type == 'tcp' and (packet.tcp.srcport == "80" or packet.tcp.srcport == "443"):
                proc_name = get_hostname_by_ip(packet.ip.src)
            elif type == 'udp' and (packet.udp.srcport == "80" or packet.udp.srcport == "443"):
                proc_name = get_hostname_by_ip(packet.ip.src)

            cachedPorts[port] = proc_name
        else:
            proc_name = cachedPorts[port]

        if proc_name is None:
            msg = f"R {port} {packet.ip.src} {length}"
        else:
            msg = f"R {port} {proc_name.replace(" ", "_")} {length}"
    # Sending packets
    else: 
        port = int(packet.tcp.srcport) if type == 'tcp' else int(packet.udp.srcport)

        if port not in cachedPorts:
            proc_name = find_processname_by_pid(find_pid_by_port(port))

            # If a packet is received on port 80 or 443, get the hostname by IP
            if type == 'tcp' and (packet.tcp.dstport == "80" or packet.tcp.dstport == "443"):
                proc_name = get_hostname_by_ip(packet.ip.dst)
            elif type == 'udp' and (packet.udp.dstport == "80" or packet.udp.dstport == "443"):
                proc_name = get_hostname_by_ip(packet.ip.dst)

            cachedPorts[port] = proc_name
        else:
            proc_name = cachedPorts[port]

        if proc_name is None:
            msg = f"S {port} {packet.ip.dst} {length}"
        else:
            msg = f"S {port} {proc_name.replace(" ", "_")} {length}"

    return msg

def resolve_packets(capture, websocket):
    for packet in capture.sniff_continuously():
        try:
            if hasattr(packet, 'tcp'):
                msg = create_message(packet, 'tcp')
            elif hasattr(packet, 'udp'):
                msg = create_message(packet, 'udp')
            else:
                msg = None
        except AttributeError:
            msg = None

        if msg is not None:
            try:
                websocket.send(msg)
            except Exception as e:
                print(f"[-] Error sending message: {e}")
                return
            
def main():
    uri = "ws://localhost:50558/python"

    global host_mac
    host_mac = get_mac_address(host_interface)
    if not host_mac:
        print("[-] MAC address not found.")
        return

    host_mac = host_mac.lower().replace("-", ":")

    capture = pyshark.LiveCapture(interface=host_interface)

    try:
        with connect(uri) as websocket:
            resolve_packets(capture, websocket)
    except Exception as e:
        print(f"[-] Error connecting to WebSocket: {e}")

if __name__ == "__main__":
    main()
