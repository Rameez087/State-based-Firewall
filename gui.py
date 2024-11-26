from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QTableWidget, QTableWidgetItem, QWidget, QTabWidget, QPushButton
)
from firewall_core import load_rules, add_rule, remove_rule
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLineEdit, QComboBox, QPushButton, QLabel, QMessageBox
from firewall_core import add_rule, load_rules
import time 

class AddRuleDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Rule")
        self.setModal(True)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Input fields
        self.src_ip_input = QLineEdit("*")
        layout.addWidget(QLabel("Source IP (e.g., 192.168.1.100 or *):"))
        layout.addWidget(self.src_ip_input)

        self.src_port_input = QLineEdit("*")
        layout.addWidget(QLabel("Source Port (e.g., 12345 or *):"))
        layout.addWidget(self.src_port_input)

        self.dst_ip_input = QLineEdit("*")
        layout.addWidget(QLabel("Destination IP (e.g., 192.168.1.1 or *):"))
        layout.addWidget(self.dst_ip_input)

        self.dst_port_input = QLineEdit("*")
        layout.addWidget(QLabel("Destination Port (e.g., 80 or *):"))
        layout.addWidget(self.dst_port_input)

        self.protocol_input = QComboBox()
        self.protocol_input.addItems(["*", "tcp", "udp"])
        layout.addWidget(QLabel("Protocol:"))
        layout.addWidget(self.protocol_input)

        # Add button
        self.add_button = QPushButton("Add")
        self.add_button.clicked.connect(self.accept)
        layout.addWidget(self.add_button)

        self.setLayout(layout)

    def get_rule(self):
        return {
            "src_ip": self.src_ip_input.text(),
            "src_port": self.src_port_input.text(),
            "dst_ip": self.dst_ip_input.text(),
            "dst_port": self.dst_port_input.text(),
            "protocol": self.protocol_input.currentText()
        }


class FirewallGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firewall Application")
        self.setGeometry(100, 100, 800, 600)

        self.initUI()

        # Initialize tables for allowed and blocked packets
        self.allowed_packets = []
        self.blocked_packets = []

    def initUI(self):
        layout = QVBoxLayout()

        # Tabs for rules, allowed, and blocked traffic
        self.tab_widget = QTabWidget()

        # Tab 1: Rules
        self.rules_tab = QWidget()
        self.init_rules_tab()
        self.tab_widget.addTab(self.rules_tab, "Rules")

        # Tab 2: Allowed Packets
        self.allowed_tab = QWidget()
        self.init_allowed_tab()
        self.tab_widget.addTab(self.allowed_tab, "Allowed Packets")

        # Tab 3: Blocked Packets
        self.blocked_tab = QWidget()
        self.init_blocked_tab()
        self.tab_widget.addTab(self.blocked_tab, "Blocked Packets")

        # Tab 4: Active Connections
        self.connections_tab = QWidget()
        self.init_connections_tab()
        self.tab_widget.addTab(self.connections_tab, "Active Connections")

        # Tab 5: Invalid Packets
        self.invalid_packets_tab = QWidget()
        self.init_invalid_packets_tab()
        self.tab_widget.addTab(self.invalid_packets_tab, "Invalid Packets")

         # Tab 6: Expired UDP Connections
        self.expired_udp_tab = QWidget()
        self.init_expired_udp_tab()
        self.tab_widget.addTab(self.expired_udp_tab, "Expired UDP Connections")

        layout.addWidget(self.tab_widget)
        main_widget = QWidget()
        main_widget.setLayout(layout)
        self.setCentralWidget(main_widget)

    def init_rules_tab(self):
        layout = QVBoxLayout()

        # Table for rules
        self.rules_table = QTableWidget(0, 6)  # Adjusted for new rule fields
        self.rules_table.setHorizontalHeaderLabels(["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", " "])
        layout.addWidget(self.rules_table)

        # Button to add rules
        add_rule_button = QPushButton("Add Rule")
        add_rule_button.clicked.connect(self.add_rule)
        layout.addWidget(add_rule_button)

        self.rules_tab.setLayout(layout)
        self.refresh_rules()

    def init_allowed_tab(self):
        layout = QVBoxLayout()

        # Table for allowed packets
        self.allowed_table = QTableWidget(0, 5)
        self.allowed_table.setHorizontalHeaderLabels(["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol"])
        layout.addWidget(self.allowed_table)

        self.allowed_tab.setLayout(layout)

    def init_blocked_tab(self):
        layout = QVBoxLayout()

        # Table for blocked packets
        self.blocked_table = QTableWidget(0, 5)
        self.blocked_table.setHorizontalHeaderLabels(["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol"])
        layout.addWidget(self.blocked_table)

        self.blocked_tab.setLayout(layout)

    def add_rule(self):
        dialog = AddRuleDialog(self)
        if dialog.exec_():  # If the dialog was accepted
            rule = dialog.get_rule()
            # Validate the rule (optional)
            for field in ["src_port", "dst_port"]:
                if rule[field] != "*" and not rule[field].isdigit():
                    QMessageBox.warning(self, "Invalid Input", f"{field.replace('_', ' ').capitalize()} must be a number or '*'.")
                    return
            add_rule(rule["src_ip"], rule["src_port"], rule["dst_ip"], rule["dst_port"], rule["protocol"])
            self.refresh_rules()

    def refresh_rules(self):
        print("refresh_rules")

        self.rules_table.setRowCount(0)
        rules = load_rules()
        print(rules)  # Debug: Check the structure of rules
        if not rules:  # Handle case where no rules exist
            print("No rules found.")
            return  # Exit the method, nothing to display

        for rule in rules:
            row = self.rules_table.rowCount()
            self.rules_table.insertRow(row)
            
            # Add the rule details to the table
            for col, key in enumerate(["src_ip", "src_port", "dst_ip", "dst_port", "protocol"]):
                value = rule.get(key, "*")  # Default to '*' if key is missing
                self.rules_table.setItem(row, col, QTableWidgetItem(str(value)))

            # Add the "Remove" button
            remove_button = QPushButton("Remove")
            remove_button.clicked.connect(lambda checked, rule=rule: self.remove_rule(rule))
            self.rules_table.setCellWidget(row, 5, remove_button)  # Place the button in the 6th column


    def add_packet_to_table(self, table, packet_info):

        """Helper function to add a packet to a table."""
        row = table.rowCount()
        table.insertRow(row)
        for col, key in enumerate(["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]):
            table.setItem(row, col, QTableWidgetItem(str(packet_info[key])))

    def log_packet(self, packet_info, allowed):
        """Log a packet to the respective tab."""
        if allowed:
            self.allowed_packets.append(packet_info)
            self.add_packet_to_table(self.allowed_table, packet_info)
        else:
            self.blocked_packets.append(packet_info)
            self.add_packet_to_table(self.blocked_table, packet_info)

# State Connections GUI

    def init_connections_tab(self):
        layout = QVBoxLayout()

        # Table for active connections
        self.connections_table = QTableWidget(0, 5)
        self.connections_table.setHorizontalHeaderLabels(["Src IP", "Src Port", "Dst IP", "Dst Port", "State"])
        layout.addWidget(self.connections_table)

        self.connections_tab.setLayout(layout)

    def update_connections_table(self, connection_table):

        """Updates the connections table with active connections."""
        self.connections_table.setRowCount(0)  # Clear the table
        for (src_ip, src_port, dst_ip, dst_port), state in connection_table.items():
            row = self.connections_table.rowCount()
            self.connections_table.insertRow(row)
            self.connections_table.setItem(row, 0, QTableWidgetItem(src_ip))
            self.connections_table.setItem(row, 1, QTableWidgetItem(str(src_port)))
            self.connections_table.setItem(row, 2, QTableWidgetItem(dst_ip))
            self.connections_table.setItem(row, 3, QTableWidgetItem(str(dst_port)))
            self.connections_table.setItem(row, 4, QTableWidgetItem(state))

# Invalid packets
    def init_invalid_packets_tab(self):
        layout = QVBoxLayout()

        # Table for invalid packets
        self.invalid_packets_table = QTableWidget(0, 5)
        self.invalid_packets_table.setHorizontalHeaderLabels(["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol"])
        layout.addWidget(self.invalid_packets_table)

        self.invalid_packets_tab.setLayout(layout)

    def log_invalid_packet(self, packet_info):
        

        #print(f"LOGGING INVALID PACKET")
        """Logs an invalid packet to the invalid packets table."""
        row = self.invalid_packets_table.rowCount()
        self.invalid_packets_table.insertRow(row)
        for col, key in enumerate(["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]):
            self.invalid_packets_table.setItem(row, col, QTableWidgetItem(str(packet_info[key])))
        
    def init_expired_udp_tab(self):
        layout = QVBoxLayout()

        # Table for expired UDP connections
        self.expired_udp_table = QTableWidget(0, 5)
        self.expired_udp_table.setHorizontalHeaderLabels(["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol"])
        layout.addWidget(self.expired_udp_table)

        self.expired_udp_tab.setLayout(layout)

    def update_connection_table(self, packet_info, state):
        key = (packet_info["src_ip"], packet_info["src_port"], packet_info["dst_ip"], packet_info["dst_port"])
        
        if state == "new":
            # Add the connection with the current timestamp
            self.connection_table[key] = {"state": "new", "start_time": time()}
        elif state == "established":
            self.connection_table[key]["state"] = "established"  # Update the state to established
        elif state == "closed":
            self.connection_table.pop(key, None)  # Remove closed connections
        elif state == "no connection":
            self.connection_table[key] = {"state": "no connection", "start_time": time()}  # Add no connection with timestamp

    def cleanup_udp_connections(self):
        current_time = time()
        keys_to_remove = []

        for key, value in self.connection_table.items():
            # Check if this is a UDP connection and if it has been in the table for more than 30 seconds
            if value["state"] == "no connection":
                if current_time - value["start_time"] > 30:  # 30 seconds timeout
                    keys_to_remove.append(key)

        # Remove expired UDP connections and add them to the expired list for the GUI
        for key in keys_to_remove:
            expired_connection = self.connection_table.pop(key)
            self.expired_udp_connections.append(expired_connection)  # Add to expired list
            self.add_expired_udp_to_table(expired_connection)

    def add_expired_udp_to_table(self, connection_info):
        """Add expired UDP connection info to the expired UDP table."""
        row = self.expired_udp_table.rowCount()
        self.expired_udp_table.insertRow(row)
        self.expired_udp_table.setItem(row, 0, QTableWidgetItem(connection_info["src_ip"]))
        self.expired_udp_table.setItem(row, 1, QTableWidgetItem(connection_info["dst_ip"]))
        self.expired_udp_table.setItem(row, 2, QTableWidgetItem(str(connection_info["src_port"])))
        self.expired_udp_table.setItem(row, 3, QTableWidgetItem(str(connection_info["dst_port"])))
        self.expired_udp_table.setItem(row, 4, QTableWidgetItem(connection_info["state"]))


    def remove_rule(self, rule):
        # Remove the rule from the backend (e.g., the rules file)
        result = remove_rule(rule["src_ip"], rule["src_port"], rule["dst_ip"], rule["dst_port"], rule["protocol"])
        
        if result:
            # If rule was successfully removed, refresh the rules table
            QMessageBox.information(self, "Rule Removed", "The rule has been successfully removed.")
            self.refresh_rules()
        else:
            QMessageBox.warning(self, "Error", "Failed to remove the rule.")
