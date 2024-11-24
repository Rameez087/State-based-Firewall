import threading
from gui import FirewallGUI
from firewall_core import monitor_traffic, match_packet, load_rules, is_valid_packet, is_packet_state
from PyQt5.QtWidgets import QApplication

connection_table = {}  # store the active connections

def handle_packet(packet_info, gui):
    rules = load_rules()



    # Extract connection details (this is just an example, modify as needed)
    connection_key = (packet_info["src_ip"], packet_info["src_port"], packet_info["dst_ip"], packet_info["dst_port"])

    # # Check if the packet matches an existing connection
    # if connection_key in connection_table:
    #     state = connection_table[connection_key]
    #     if state == "new" and packet_info["flags"] == "SYN-ACK":
    #         connection_table[connection_key] = "established"  # Change state to established
    # else:
    #     # If it's a new connection, add it to the table
    #     if packet_info["protocol"] == "TCP" and packet_info["flags"] == "SYN":
    #         connection_table[connection_key] = "new"
    #     elif packet_info["protocol"] == "UDP":
    #         connection_table[connection_key] = "no connection"
    #     else:
    #         connection_table[connection_key] = "established"

    if is_valid_packet(packet_info):
        state = is_packet_state(packet_info)
        print(f"state: {state}")

        connection_table[connection_key] = state

    # Check if the packet was explicitly marked as invalid
    if packet_info.get("invalid"):
        print(f"Handling invalid packet: {packet_info}")
        gui.log_invalid_packet(packet_info)  # Log invalid packet in the GUI
    

    if match_packet(packet_info, rules):  # If it matches a blocking rule
        print(f"Blocked packet: {packet_info}")
        gui.log_packet(packet_info, allowed=False)
    else:
        print(f"Allowed packet: {packet_info}")
        gui.log_packet(packet_info, allowed=True)

    # Update the active connections table in the GUI
    gui.update_connections_table(connection_table) 





if __name__ == "__main__":
    app = QApplication([])

    # Create the GUI instance
    gui = FirewallGUI()

    # Start monitoring in a separate thread and pass the GUI instance
    monitoring_thread = threading.Thread(
        target=monitor_traffic, args=(lambda pkt: handle_packet(pkt, gui),)
    )
    monitoring_thread.daemon = True
    monitoring_thread.start()

    # Launch the GUI
    gui.show()
    app.exec_()
