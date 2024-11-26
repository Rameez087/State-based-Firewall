import json
from scapy.all import sniff, IP, TCP, UDP

# File for storing rules
RULES_FILE = "rules.json"


# Load rules from JSON file
def load_rules():
    try:
        with open(RULES_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return []

# Save rules to JSON file
def save_rules(rules):
    with open(RULES_FILE, "w") as file:
        json.dump(rules, file, indent=4)

def add_rule(src_ip, src_port, dst_ip, dst_port, protocol):
    """
    Adds a blocking rule to the firewall.

    :param src_ip: Source IP address or "*" for any.
    :param src_port: Source port or "*" for any.
    :param dst_ip: Destination IP address or "*" for any.
    :param dst_port: Destination port or "*" for any.
    :param protocol: Protocol ("tcp", "udp", or "*").
    """
    rules = load_rules()
    rules.append({
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol
    })
    save_rules(rules)

# Remove a rule by index
def remove_rule(index):
    rules = load_rules()
    if 0 <= index < len(rules):
        rules.pop(index)
        save_rules(rules)

def match_packet(packet_info, rules):
    """
    Checks if a packet matches any blocking rule.

    :param packet_info: Dictionary containing packet details.
    :param rules: List of blocking rules.
    :return: True if the packet matches a rule (should be blocked), False otherwise.
    """
    for rule in rules:
        if (rule["src_ip"] == "*" or rule["src_ip"] == packet_info["src_ip"]) and \
           (rule["src_port"] == "*" or rule["src_port"] == packet_info["src_port"]) and \
           (rule["dst_ip"] == "*" or rule["dst_ip"] == packet_info["dst_ip"]) and \
           (rule["dst_port"] == "*" or rule["dst_port"] == packet_info["dst_port"]) and \
           (rule["protocol"] == "*" or rule["protocol"] == packet_info["protocol"]):
            return True  # Block the packet
    return False  # Allow the packet



# Track active connections
connection_table = {}


# Real-time traffic monitoring
def monitor_traffic(callback):
    """
    Monitors network traffic in real-time and applies callback functions to handle packets.

    :param callback: A function that processes packet information.
    """
    def packet_handler(packet):
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = "tcp"
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = "udp"
            else:
                src_port = dst_port = None

            packet_info = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol
            }

            # Determine packet state
            state = determine_state(packet)
            if state:
                update_connection_table(packet_info, state)

            # Check if packet is valid based on state
            if state == "new" or is_valid_packet(packet_info):
                callback(packet_info)
            else:
                print(f"Invalid packet dropped: {packet_info}")
                # Forward invalid packets to the callback for GUI logging
                packet_info["invalid"] = True  # Mark packet as invalid
                callback(packet_info)

    sniff(prn=packet_handler, store=False)



def update_connection_table(packet_info, state):
    """
    Updates the connection table based on the packet's state.
    
    :param packet_info: Dictionary containing packet details.
    :param state: The new state of the connection (e.g., "new", "established", "closed").
    """
    key = (packet_info["src_ip"], packet_info["src_port"], packet_info["dst_ip"], packet_info["dst_port"])
    
    if state == "new":
        connection_table[key] = "new"  # New connection
    elif state == "established":
        connection_table[key] = "established"  # Connection established (SYN-ACK)
    elif state == "closed":
        connection_table.pop(key, None)  # Remove closed connections
    elif state == "no connection":
        connection_table[key] = "no connection"

def determine_state(packet):
    """
    Determines the state of a packet based on its flags.
    
    :param packet: A Scapy packet object.
    :return: State as a string ("new", "established", "closed", or None).
    """
    if TCP in packet:
        flags = packet[TCP].flags
        if flags == "S":  # SYN
            return "new"  # New TCP connection (SYN)
        elif flags == "SA":  # SYN-ACK (handshake completion)
            return "established"
        elif flags == "A":  # ACK (part of the established connection)
            return "established"
        elif flags == "FA" or flags == "R":  # FIN-ACK or RST (connection termination)
            return "closed"

        
    elif UDP in packet:
        return "no connection"  # UDP does not have connection states
    else:
        return "not UDP or TCP"
    return None

def is_valid_packet(packet_info):
    """
    Checks if a packet is part of an active connection.

    :param packet_info: Dictionary with packet details.
    :return: True if the packet is valid, False otherwise.
    """
    key = (packet_info["src_ip"], packet_info["src_port"], packet_info["dst_ip"], packet_info["dst_port"])
    return key in connection_table

def is_packet_state(packet_info):
    key = (packet_info["src_ip"], packet_info["src_port"], packet_info["dst_ip"], packet_info["dst_port"])
    return connection_table[key]


def remove_rule(src_ip, src_port, dst_ip, dst_port, protocol):
    # Load existing rules
    try:
        with open("rules.json", "r") as file:
            rules = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return False  # File not found or invalid format
    
    # Filter out the rule to be removed
    new_rules = [rule for rule in rules if not (rule["src_ip"] == src_ip and 
                                                 rule["src_port"] == src_port and 
                                                 rule["dst_ip"] == dst_ip and 
                                                 rule["dst_port"] == dst_port and 
                                                 rule["protocol"] == protocol)]

    # If no rule was removed, return False
    if len(new_rules) == len(rules):
        return False
    
    # Save the updated rules back to the file
    with open("rules.json", "w") as file:
        json.dump(new_rules, file, indent=4)
    
    return True
