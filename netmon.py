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
import traceback
from concurrent.futures import ThreadPoolExecutor
import threading

host_interface = 'Ethernet'
host_mac = None

cachedPID = {} # pid -> process name
cachedPID_lock = threading.Lock()

cachedHostnames = {} # ip -> hostname
cachedHostnames_lock = threading.Lock()

processIconsSent = set() # list of processes names that had their icon sent
processIconsSent_lock = threading.Lock()

def split_last(s, delimiter):
    pos = s.rfind(delimiter)
    if pos == -1:
        return s  # If delimiter not found, return the whole string
    return s[pos + len(delimiter):]  # Return the part after the last delimiter

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
    with cachedPID_lock:
        if pid in cachedPID:
            return cachedPID[pid]
        
        exe_path = get_executable_path_by_pid(pid)
        print("Exe path: ", exe_path)

        if exe_path is None or exe_path == "":
            server_ip = get_server_ip(packet)
            cachedPID[pid] = server_ip
            return server_ip
        
        cachedPID[pid] = split_last(exe_path, "\\")

    return split_last(exe_path, "\\")

# def find_processname_by_pid(packet, pid):
#     if pid is not None:
#         try:
#             process = psutil.Process(pid)
#             return process.name()
#         except (psutil.NoSuchProcess, psutil.AccessDenied):
#             return packet.ip.src if is_receiving_packet(packet) else packet.ip.dst

#     return packet.ip.src if is_receiving_packet(packet) else packet.ip.dst

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

def create_icon_message(packet, host_port):
    pid = find_pid_by_port(host_port)

    proc_name = find_processname_by_pid(packet, pid)

    with processIconsSent_lock:
        if proc_name in processIconsSent or proc_name is None:
            return None

        exe_path = get_executable_path_by_pid(pid)
        icon = get_icon_from_exe(exe_path)
        processIconsSent.add(proc_name)

    if icon is None:
        return None
    else:
        return f"I {proc_name} {icon}"
    
def get_server_ip(packet):
    if hasattr(packet, 'ip'):
        return packet.ip.src if is_receiving_packet(packet) else packet.ip.dst
    elif hasattr(packet, 'ipv6'):
        return packet.ipv6.src if is_receiving_packet(packet) else packet.ipv6.dst
    return None

def get_host_ip(packet):
    if hasattr(packet, 'ip'):
        return packet.ip.dst if is_receiving_packet(packet) else packet.ip.src
    elif hasattr(packet, 'ipv6'):
        return packet.ipv6.dst if is_receiving_packet(packet) else packet.ipv6.src
    return None

def get_host_port(packet):
    if hasattr(packet, 'tcp'):
        if is_receiving_packet(packet):
            return packet.tcp.dstport
        else:
            return packet.tcp.srcport
    elif hasattr(packet, 'udp'):
        if is_receiving_packet(packet):
            return packet.udp.dstport
        else:
            return packet.udp.srcport
    return None

def get_server_port(packet):
    if hasattr(packet, 'tcp'):
        if is_receiving_packet(packet):
            return packet.tcp.srcport
        else:
            return packet.tcp.dstport
    elif hasattr(packet, 'udp'):
        if is_receiving_packet(packet):
            return packet.udp.srcport
        else:
            return packet.udp.dstport
    return None

# Function can only be called for tcp and udp packets
def create_message(packet):
    length = int(packet.frame_info.len)

    host_port = get_host_port(packet)
    server_port = get_server_port(packet)
    host_ip = get_host_ip(packet)
    server_ip = get_server_ip(packet)

    direction_char = 'R' if is_receiving_packet(packet) else 'S'

    hostname = None
    proc_name = find_processname_by_pid(packet, find_pid_by_port(host_port))

    # If a packet is received on port 80 or 443, get the hostname by IP
    if server_port == "80" or server_port == "443":
        with cachedHostnames_lock:
            if server_ip not in cachedHostnames:
                hostname = get_hostname_by_ip(server_ip)
                cachedHostnames[server_ip] = hostname
            else:
                hostname = cachedHostnames[server_ip]

    if hostname is not None:
        msg = f"{direction_char} {host_port} {proc_name.replace(" ", "_")} {hostname} {length}"
    else:
        msg = f"{direction_char} {host_port} {proc_name.replace(" ", "_")} _ {length}"
 
    return msg

def resolve_packet(packet, websocket):
    msg = create_message(packet)
    icon_msg = create_icon_message(packet, get_host_port(packet))

    try:
        if msg is not None:
            websocket.send(msg)
        if icon_msg is not None:
            websocket.send(icon_msg)
    except Exception as e:
        print(f"[-] Error sending message: {e}")

def capture_packets(capture, websocket):
    with ThreadPoolExecutor(max_workers=20) as executor:
        for packet in capture.sniff_continuously():
            try:
                if hasattr(packet, 'tcp') or hasattr(packet, 'udp'):
                    executor.submit(resolve_packet, packet, websocket)
            except AttributeError as e:
                traceback.print_exc()
            
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
            capture_packets(capture, websocket)
    except Exception as e:
        print(f"[-] Error connecting to WebSocket: {e}")

if __name__ == "__main__":
    main()
