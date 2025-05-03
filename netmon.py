from websockets.sync.client import connect
import pyshark
import psutil

host_interface = 'Ethernet'
host_mac = None

def get_mac_address(interface_name):
    addrs = psutil.net_if_addrs()
    for addr in addrs.get(interface_name, []):
        if addr.family == psutil.AF_LINK:
            return addr.address
    return None

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

def resolve_packets(capture, websocket):
    for packet in capture.sniff_continuously():
        try:
            packet_mac = packet.eth.dst
            length = int(packet.frame_info.len)

            if hasattr(packet, 'tcp'):
                if packet_mac == host_mac:
                    port = int(packet.tcp.dstport)
                    proc_name = find_processname_by_pid(find_pid_by_port(port))
                    if proc_name is None:
                        msg = f"R {port} UnknownProcess {length}"
                    else:
                        msg = f"R {port} {proc_name.replace(" ", "_")} {length}"
                else:
                    port = int(packet.tcp.srcport)
                    proc_name = find_processname_by_pid(find_pid_by_port(port))
                    if proc_name is None:
                        msg = f"S {port} UnknownProcess {length}"
                    else:
                        msg = f"S {port} {proc_name.replace(" ", "_")} {length}"
            elif hasattr(packet, 'udp'):
                if packet_mac == host_mac:
                    port = int(packet.udp.dstport)
                    proc_name = find_processname_by_pid(find_pid_by_port(port))
                    if proc_name is None:
                        msg = f"R {port} UnknownProcess {length}"
                    else:
                        msg = f"R {port} {proc_name.replace(" ", "_")} {length}"
                else:
                    port = int(packet.udp.srcport)
                    proc_name = find_processname_by_pid(find_pid_by_port(port))
                    if proc_name is None:
                        msg = f"S {port} UnknownProcess {length}"
                    else:
                        msg = f"S {port} {proc_name.replace(" ", "_")} {length}"
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
