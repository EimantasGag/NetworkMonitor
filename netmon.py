from websockets.sync.client import connect
import pyshark
import psutil
import socket
import win32gui
import win32ui
from PIL import Image
import win32con
from io import BytesIO
import base64

host_interface = 'Ethernet'
host_mac = None

cachedPorts = {} # port -> process name
processIconsSent = set() # list of processes names that had their icon sent

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
        return None

def find_pid_by_port(port):
    port = int(port)
    for conn in psutil.net_connections(kind='all'):
        if conn.laddr.port == port:
            if conn.pid is not None:
                return conn.pid
    return None

def get_executable_path_by_pid(pid):
    try:
        process = psutil.Process(pid)
        return process.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        return None

def find_processname_by_pid(packet, pid):
    if pid is not None:
        try:
            process = psutil.Process(pid)
            return process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            if is_receiving_packet(packet):
                return packet.ip.src
            else:
                return packet.ip.dst
    return None

def get_port(packet, direction):
    if hasattr(packet, 'tcp'):
        if direction == 'src':
            return packet.tcp.srcport
        elif direction == 'dst':
            return packet.tcp.dstport
    elif hasattr(packet, 'udp'):
        if direction == 'src':
            return packet.udp.srcport
        elif direction == 'dst':
            return packet.udp.dstport
    return None

def get_icon_from_exe(exe_path):
    try:
        # Load icon from file
        large, _ = win32gui.ExtractIconEx(exe_path, 0)
        if not large:
            return None

        # Use the large icon if available, else small
        hicon = large[0]

        # Get icon info
        hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
        hbmp = win32ui.CreateBitmap()
        hbmp.CreateCompatibleBitmap(hdc, 256, 256)

        hdc_mem = hdc.CreateCompatibleDC()
        hdc_mem.SelectObject(hbmp)
        win32gui.DrawIconEx(hdc_mem.GetHandleOutput(), 0, 0, hicon, 256, 256, 0, None, win32con.DI_NORMAL)

        bmpinfo = hbmp.GetInfo()
        bmpstr = hbmp.GetBitmapBits(True)

        image = Image.frombuffer(
            'RGBA',
            (bmpinfo['bmWidth'], bmpinfo['bmHeight']),
            bmpstr, 'raw', 'BGRA', 0, 1
        )

        buffer = BytesIO()
        image.save(buffer, format="PNG")
        image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

        return image_base64

    except Exception as e:
        return None
    
def is_receiving_packet(packet):
    return packet.eth.dst == host_mac

def create_icon_message(packet, port):
    pid = find_pid_by_port(port)

    if port not in cachedPorts:    
        proc_name = find_processname_by_pid(packet, pid)
        cachedPorts[port] = proc_name
    else:
        proc_name = cachedPorts[port]

    if proc_name in processIconsSent or proc_name is None:
        return None

    exe_path = get_executable_path_by_pid(pid)
    icon = get_icon_from_exe(exe_path)
    processIconsSent.add(proc_name)

    if icon is None:
        return None
    else:
        return f"I {proc_name} {icon} X"

# Function can only be called for tcp and udp packets
def create_message(packet):
    length = int(packet.frame_info.len)
    
    # Receiving packets
    if is_receiving_packet(packet):
        port = get_port(packet, 'dst')

        if port not in cachedPorts:
            proc_name = find_processname_by_pid(packet, find_pid_by_port(port))

            # If a packet is received on port 80 or 443, get the hostname by IP
            if get_port(packet, 'src') == "80" or get_port(packet, 'src') == "443":
                hostname = get_hostname_by_ip(packet.ip.src)
                if hostname is not None:
                    proc_name = hostname

            print("Process path: ", get_executable_path_by_pid(find_pid_by_port(port)))
            cachedPorts[port] = proc_name
        else:
            proc_name = cachedPorts[port]

        if proc_name is None:
            msg = f"R {port} {packet.ip.src} {length}"
        else:
            msg = f"R {port} {proc_name.replace(" ", "_")} {length}"
    # Sending packets
    else: 
        port = get_port(packet, 'src')

        if port not in cachedPorts:
            proc_name = find_processname_by_pid(packet, find_pid_by_port(port))

            # If a packet is received on port 80 or 443, get the hostname by IP
            if get_port(packet, 'dst') == "80" or get_port(packet, 'dst') == "443":
                hostname = get_hostname_by_ip(packet.ip.dst)
                if hostname is not None:
                    proc_name = hostname

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
            if hasattr(packet, 'tcp') or hasattr(packet, 'udp'):
                msg = create_message(packet)

                if is_receiving_packet(packet):
                    icon_msg = create_icon_message(packet, get_port(packet, 'dst'))
                else:
                    icon_msg = create_icon_message(packet, get_port(packet, 'src'))
            else:
                msg = None
        except AttributeError:
            msg = None

        try:
            if msg is not None:
                websocket.send(msg)
            if icon_msg is not None:
                websocket.send(icon_msg)
        except Exception as e:
            print(f"[-] Error sending message: {e}")
            
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
