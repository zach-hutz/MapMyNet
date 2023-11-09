import sys
import nmap
import os
import json
import networkx as nx
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QInputDialog, QMessageBox,
                             QLineEdit, QPushButton, QRadioButton, QCheckBox, QProgressBar, QTextEdit, QFileDialog,
                             QLabel, QButtonGroup, QGridLayout, QTreeWidget, QTreeWidgetItem)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtWidgets import QMenu
from pyvis.network import Network
import webbrowser
from ipaddress import ip_address
from scapy.all import get_if_addr, ARP, Ether, srp, conf

class ExclusiveCheckBox(QCheckBox):
    """
    A checkbox that can only be checked or unchecked by clicking on it.
    When clicked, it emits a toggled signal with False if it was already checked,
    and True if it was unchecked and is now checked.
    """
    
    def __init__(self, *args, **kwargs):
        super(ExclusiveCheckBox, self).__init__(*args, **kwargs)
        self.setChecked(False)

    def mousePressEvent(self, event):
        """
        This method is called when the mouse button is pressed over the checkbox.
        If the checkbox is already checked, it will emit the toggled signal with False, as if it was unchecked.
        If the checkbox is not already checked, it will proceed with the normal behavior which will check the checkbox.
        """
        if self.isChecked():
            # Emit the toggled signal with False, as if it was unchecked
            self.toggled.emit(False)
            self.setChecked(False)
        else:
            # If not already checked, proceed with the normal behavior which will check the checkbox
            super(ExclusiveCheckBox, self).mousePressEvent(event)

class CustomTreeWidget(QTreeWidget):
    """
    A custom QTreeWidget that allows copying text from the second column of selected items.
    """
    def __init__(self, parent=None):
        super().__init__(parent)

    def contextMenuEvent(self, event):
        """
        Displays a context menu when the user right-clicks on the widget.
        The context menu contains a "Copy" action that, when triggered,
        calls the copy_text method to copy the selected text to the clipboard.
        """
        contextMenu = QMenu(self)
        copyAction = contextMenu.addAction("Copy")
        action = contextMenu.exec_(self.mapToGlobal(event.pos()))

        if action == copyAction:
            self.copy_text()

    def copy_text(self):
        """
        Copies the text from the second column of the selected item to the clipboard.
        """
        selected_items = self.selectedItems()
        if selected_items:
            text_to_copy = selected_items[0].text(1)  # Assuming you want to copy text from the second column
            QApplication.clipboard().setText(text_to_copy)

class ClickableLineEdit(QLineEdit):
    """
    A custom QLineEdit widget that emits a clicked signal when clicked.
    """
    clicked = pyqtSignal()

    def mousePressEvent(self, event):
        """
        This method is called when a mouse button is pressed while the mouse cursor is inside the widget.
        It emits a clicked signal.
        """
        super().mousePressEvent(event)
        self.clicked.emit()

class ScanThread(QThread):
    """
    A QThread subclass that performs network scanning using Nmap.

    Attributes:
        update_progress (pyqtSignal): A signal emitted to update the progress of the scan.
        finished (pyqtSignal): A signal emitted when the scan is finished.
        error_occurred (pyqtSignal): A signal emitted when an error occurs during the scan.
        result_acquired (pyqtSignal): A signal emitted when the scan results are acquired.

    Args:
        ips (list): A list of IP addresses to scan.
        scan_args (str): A string of Nmap scan arguments.
    """
    update_progress = pyqtSignal(int)
    finished = pyqtSignal()
    error_occurred = pyqtSignal(str)
    result_acquired = pyqtSignal(dict)

    def __init__(self, ips, scan_args):
        super().__init__()
        self.ips = ips
        self.scan_args = scan_args

    def run(self):
        nm = nmap.PortScanner()
        data = {}
        for i, ip in enumerate(self.ips):
            try:
                nm.scan(hosts=ip, arguments=self.scan_args)
                for host in nm.all_hosts():
                    if host not in data:
                        data[host] = {}
                    for proto in nm[host].all_protocols():
                        for port in sorted(nm[host][proto].keys()):
                            service_info = nm[host][proto][port]

                            # Create a dictionary for each port with the service info
                            port_data = {
                                'state': service_info['state'],
                                'name': service_info.get('name', '').upper(),
                                'product': service_info.get('product', ''),
                                'version': service_info.get('version', ''),
                                'extra': service_info.get('extrainfo', ''),
                                'cpe': service_info.get('cpe', '')
                            }

                            # If the 'script' key exists in the service_info, add it to the port_data
                            if 'script' in service_info:
                                for script, output in service_info['script'].items():
                                    if "ERROR" not in output:
                                        # Add the script name and output to the port_data as a key-value pair
                                        port_data[script] = output



                            # Add the port_data dictionary to the data under the corresponding host and port
                            data[host][port] = port_data

                self.result_acquired.emit(data)  # Emit the result after processing each host
            except nmap.PortScannerError as e:
                self.error_occurred.emit(str(e))
                return
            self.update_progress.emit(i + 1)  # Update progress after each scan
        self.finished.emit()  # Emit signal when scanning is finished

class NmapGUI(QMainWindow):
    class MapMyNet:
        def __init__(self):
            """
            Initializes the MapMyNet class.

            Attributes:
            - data: a dictionary to store the network data
            - filename_to_save: the name of the file to save the results to
            - tab_widget: a QTabWidget to display the input, results, and visualize tabs
            - user_checked_save_to_file: a boolean indicating whether the user wants to save the results to a file
            - input_tab: a QWidget to display the input tab
            - results_tree: a CustomTreeWidget to display the results in a tree view
            - visualize_tab: a QWidget to display the visualize tab
            """
            super().__init__()

            self.data = {}
            self.filename_to_save = None
            self.setWindowTitle("MapMyNet (Network Reconaissance)")
            self.setGeometry(100, 100, 700, 00)

            self.tab_widget = QTabWidget(self)
            self.setCentralWidget(self.tab_widget)
            self.user_checked_save_to_file = True

            # Input Tab
            self.input_tab = QWidget()
            self.tab_widget.addTab(self.input_tab, "Input")
            self.setup_input_tab()

            # Results Tab
            self.results_tree = CustomTreeWidget(self)  # Use the subclassed CustomTreeWidget
            self.results_tree.setHeaderLabels(["Hosts and Ports", "Details"])
            self.tab_widget.addTab(self.results_tree, "Results")

            # Visualize Tab
            self.visualize_tab = QWidget()
            self.tab_widget.addTab(self.visualize_tab, "Visualize")
            self.setup_visualize_tab()

            self.results_tree.setColumnWidth(0, self.results_tree.width() // 2)
            self.results_tree.setColumnWidth(1, self.results_tree.width() // 2)
            self.results_tree.resizeEvent = self.resize_tree_columns

    def resize_tree_columns(self, event):
        """
        Resizes the columns of the results tree to be half the width of the tree widget.
        """
        self.results_tree.setColumnWidth(0, self.results_tree.width() // 2)
        self.results_tree.setColumnWidth(1, self.results_tree.width() // 2)

    def setup_input_tab(self):
        """
        Sets up the input tab with various widgets such as QLineEdit, QRadioButton, QCheckBox, QPushButton, and QProgressBar.
        The widgets are arranged using QGridLayout.
        """
        layout = QGridLayout(self.input_tab)
        layout.setSpacing(20)  # Set spacing between widgets to 20 pixels (roughly 2")

        # Entry for host or file
        self.host_entry = ClickableLineEdit("Enter host or select a file", self.input_tab)
        self.host_entry.setStyleSheet("color: white; background-color: grey")
        self.host_entry.clicked.connect(self.on_entry_click)
        layout.addWidget(self.host_entry, 0, 0, 1, 2)

        self.file_button = QPushButton("Select File", self.input_tab)
        self.file_button.clicked.connect(self.select_file)
        layout.addWidget(self.file_button, 0, 2)

        # Radiobuttons for Basic Scans
        self.basic_scan_label = QLabel("Ports", self.input_tab)
        layout.addWidget(self.basic_scan_label, 1, 0)
        layout.setRowMinimumHeight(1, 10)  # Set minimum height for the row to 10 pixels (roughly 1")

        self.scan_option = QButtonGroup(self.input_tab)
        self.full_ports_rb = QRadioButton("All Ports", self.input_tab)
        self.common_ports_rb = QRadioButton("Most Common Ports", self.input_tab)
        self.specify_port_rb = QRadioButton("Specify a Port", self.input_tab)
        self.specify_port_rb.clicked.connect(self.specify_port)

        self.scan_option.addButton(self.full_ports_rb)
        self.scan_option.addButton(self.common_ports_rb)
        self.scan_option.addButton(self.specify_port_rb)

        layout.addWidget(self.full_ports_rb, 2, 0)
        layout.addWidget(self.common_ports_rb, 3, 0)
        layout.addWidget(self.specify_port_rb, 4, 0)

        self.full_ports_rb.clicked.connect(self.specify_port)
        self.common_ports_rb.clicked.connect(self.specify_port)

        self.specify_port_entry = QLineEdit(self.input_tab)
        layout.addWidget(self.specify_port_entry, 5, 0)

        # Checkboxes for Nmap Flags
        self.flags_label = QLabel("Scan Flags", self.input_tab)
        layout.addWidget(self.flags_label, 1, 1)
        layout.setRowMinimumHeight(1, 10)  # Set minimum height for the row to 10 pixels (roughly 1")

        self.flag_ss_cb = QCheckBox("-sS", self.input_tab)
        self.flag_sv_cb = QCheckBox("-sV", self.input_tab)
        self.flag_a_cb = QCheckBox("-A", self.input_tab)
        self.flag_pn_cb = QCheckBox("-Pn", self.input_tab)

        # Grouping -T flags
        self.flag_t0_cb = ExclusiveCheckBox("-T0", self.input_tab)
        self.flag_t1_cb = ExclusiveCheckBox("-T1", self.input_tab)
        self.flag_t2_cb = ExclusiveCheckBox("-T2", self.input_tab)
        self.flag_t3_cb = ExclusiveCheckBox("-T3", self.input_tab)
        self.flag_t4_cb = ExclusiveCheckBox("-T4", self.input_tab)
        self.flag_t5_cb = ExclusiveCheckBox("-T5", self.input_tab)

        layout.addWidget(self.flag_ss_cb, 2, 1)
        layout.addWidget(self.flag_sv_cb, 3, 1)
        layout.addWidget(self.flag_a_cb, 4, 1)
        layout.addWidget(self.flag_pn_cb, 2, 2)


        layout.addWidget(self.flag_t0_cb, 3, 2)
        layout.addWidget(self.flag_t1_cb, 4, 2)
        layout.addWidget(self.flag_t2_cb, 5, 2)
        layout.addWidget(self.flag_t3_cb, 2, 3)
        layout.addWidget(self.flag_t4_cb, 3, 3)
        layout.addWidget(self.flag_t5_cb, 4, 3)

        self.t_flags_group = QButtonGroup(self.input_tab)
        self.t_flags_group.setExclusive(False)
        self.add_to_t_group(self.flag_t0_cb)
        self.add_to_t_group(self.flag_t1_cb)
        self.add_to_t_group(self.flag_t2_cb)
        self.add_to_t_group(self.flag_t3_cb)
        self.add_to_t_group(self.flag_t4_cb)
        self.add_to_t_group(self.flag_t5_cb)

        # Checkbox to save to file
        self.save_to_file_cb = QCheckBox("Save to File", self.input_tab)
        self.save_to_file_cb.toggled.connect(self.prompt_for_filename)
        layout.addWidget(self.save_to_file_cb, 8, 0, 1, 3)

        # Button to start scan
        self.scan_button = QPushButton("Start Scan", self.input_tab)
        self.scan_button.clicked.connect(self.run_scan)
        layout.addWidget(self.scan_button, 6, 0, 1, 3)

        # Progress bar
        self.progress = QProgressBar(self.input_tab)
        self.progress.setVisible(False)  # Set progress bar to be invisible by default
        layout.addWidget(self.progress, 7, 0, 1, 3)
        self.specify_port_entry.setFixedWidth(100)
        self.specify_port_entry.setVisible(False)

        # Checkbox for auto discovery
        self.net_discovery_cb = QCheckBox("Auto Discovery", self.input_tab)
        self.net_discovery_cb.toggled.connect(self.toggle_net_discovery)
        layout.addWidget(self.net_discovery_cb, 0, 3)  # Adjust the position as needed

    def add_to_t_group(self, checkbox):
        """
        Adds a checkbox to the t_flags_group and connects its toggled signal to the handle_t_flag_toggle method.

        Args:
            checkbox (QCheckBox): The checkbox to add to the t_flags_group.
        """
        self.t_flags_group.addButton(checkbox)
        checkbox.toggled.connect(lambda checked, cb=checkbox: self.handle_t_flag_toggle(checked, cb))

    def handle_t_flag_toggle(self, checked, checkbox):
            """
            Handles the toggling of a t-flag checkbox.

            Args:
                checked (bool): Whether the checkbox is checked or not.
                checkbox (QCheckBox): The checkbox that was toggled.
            """
            if checked:
                # If the checkbox is checked, uncheck all others
                for button in self.t_flags_group.buttons():
                    if button != checkbox:
                        button.setChecked(False)

    def setup_visualize_tab(self):
        """
        Sets up the 'Visualize' tab in the GUI, including a button to visualize the results.
        """
        layout = QVBoxLayout(self.visualize_tab)
        self.visualize_button = QPushButton("Visualize Results", self.visualize_tab)
        self.visualize_button.clicked.connect(self.visualize_results)
        layout.addWidget(self.visualize_button)

    def prompt_for_filename(self, checked):
            """
            Prompts the user to select a filename to save the results to.

            Args:
                checked (bool): Whether or not the "Save to File" checkbox is checked.

            Returns:
                None
            """
            if checked:
                filename, _ = QFileDialog.getSaveFileName(self, "Save Results As", "", "Text Files (*.txt);;Web Pages (*.html);;JSON (*.json);;CSV (*.csv);;All Files (*)")
                if filename:  # If user provided a filename
                    self.filename_to_save = filename  # Store the filename to use later when saving results
                else:
                    self.save_to_file_cb.setChecked(False)  # Uncheck the checkbox if no filename was provided
                    self.filename_to_save = None  # Set filename_to_save to None if no file was selected

    def specify_port(self):
            """
            Displays a dialog box to allow the user to specify a custom port number.
            If the user clicks OK without entering a port or clicks Cancel, the radio button is set to "Most Common Ports".
            """
            if self.specify_port_rb.isChecked():
                self.specify_port_entry.setVisible(True)
                port, ok = QInputDialog.getText(self, "Specify Port", "Enter the port number:")
                if ok and port:
                    self.specify_port_entry.setText(port)
                else:
                    # If the user clicks OK without entering a port or clicks Cancel, set the radio button to "Most Common Ports"
                    self.common_ports_rb.setChecked(True)
                    self.specify_port_entry.clear()  # Clear the input box
                    self.specify_port_entry.setVisible(False)
                self.specify_port_entry.setFixedWidth(100)  # Set the fixed width again after the dialog is closed
            else:
                self.specify_port_entry.clear()  # Clear the input box
                self.specify_port_entry.setVisible(False)

    def on_entry_click(self):
            """
            Clears the host_entry text field and sets its background color to grey when the user clicks on it.
            """
            if self.host_entry.text() == "Enter host or select a file":
                self.host_entry.clear()
                self.host_entry.setStyleSheet("color: white; background-color: grey")

    def on_focusout(self):
        """
        This method is called when the focus leaves the host_entry field.
        If the field is empty, it sets the default text and background color.
        """
        if not self.host_entry.text():
            self.host_entry.setText("Enter host or select a file")
            self.host_entry.setStyleSheet("color: white; background-color: grey")

    def visualize_results(self):
        """
        Visualizes the results of a network scan by creating a network graph using the NetworkX library and displaying it in a web browser.
        If there is no data to visualize, a message box will be displayed informing the user to run a scan first.
        """
            
        if not hasattr(self, 'data') or not self.data:
            QMessageBox.information(self, "No Data", "No data to visualize. Please run a scan first.")
            return

        net = Network(notebook=True)
        port_nodes = {}  # Dictionary to track ports and connect multiple hosts to the same port node

        # Assuming data is a class variable now
        for host, ports in self.data.items():
            net.add_node(host, color='blue', title=f"Host: {host}")
            for port, details in ports.items():
                if details['state'] == 'open':
                    port_label = f"Port {port}"
                    # If the port node does not exist, create it
                    if port_label not in port_nodes:
                        port_node_id = f"port_{port}"  # Create a unique ID for the port node
                        net.add_node(port_node_id, color='green', title=port_label, label=port_label)
                        port_nodes[port_label] = port_node_id
                    # Connect the host to the port
                    net.add_edge(host, port_nodes[port_label], color='black')

        # Save and open the network graph
        net.show("temp/network.html")
        full_path = os.path.abspath("temp/network.html")
        webbrowser.open(f'file://{full_path}')

    def select_file(self):
        """
        Opens a file dialog to allow the user to select a file, and sets the text of the host_entry field to the selected file path.
        """
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.host_entry.setText(file_path)

    def enumerate_ips(self, start_ip, end_ip):
        """
        Enumerate all IP addresses between start_ip and end_ip (inclusive).
            
        Args:
            start_ip (str): The starting IP address.
            end_ip (str): The ending IP address.
            
        Returns:
            list: A list of all IP addresses between start_ip and end_ip (inclusive).
        """
        start = int(ip_address(start_ip))
        end = int(ip_address(start_ip.split('.')[0] + '.' + start_ip.split('.')[1] + '.' + start_ip.split('.')[2] + '.' + end_ip))
        return [str(ip_address(ip)) for ip in range(start, end + 1)]
    
    def run_scan(self):
        ips = []
        #TODO In Progress - Add network discovery through ARP enumeration
        if self.net_discovery_cb.isChecked():
            ip_address = get_if_addr(conf.iface)

            # Replace last octet with 0/24 to get network address
            ip_address = ip_address.rsplit('.', 1)[0] + '.0/24'

            # Create ARP request packet
            arp = ARP(pdst=ip_address)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Send the packet and get the responses
            result = srp(packet, timeout=2, verbose=0)[0]

            # Parse the result
            for sent, received in result:
                ips.append(received.prsc)
        else:
            # Validate a target is entered
            target = self.host_entry.text()
            if not target or target == "Enter host or select a file":
                QMessageBox.critical(self, "Error", "Please enter a host or select a file.")
                return
        
        # Validate a scan type is selected
        if not self.scan_option.checkedButton():
            QMessageBox.critical(self, "Error", "Please select a scan type.")
            return
        
        # Support for multiple targets
        if ',' in target:
            targets = target.strip().split(',')
            for ip in targets:
                ips.append(ip.strip())

        # Support for text files
        elif target.endswith('.txt'):
            with open(target, 'r') as f:
                ips = [line.strip() for line in f.readlines()]
        
        # Support for IP ranges
        elif '-' in target:
            # Get the first and last IP address in the range
            first_ip, last_ip = target.split('-')

            # Append IP addresses in the range to the ips list
            ips.extend(self.enumerate_ips(first_ip, last_ip))
        else:
            ips.append(target)
        
        # Display progress bar
        self.progress.setValue(0)
        self.progress.setMaximum(len(ips))
        self.progress.setVisible(True)
        self.results_tree.clear()

        # Retrieve scan options
        scan_type = self.scan_option.checkedButton().text()
        scan_args = '-F'  # Default to fast scan
        if scan_type == "All Ports":
            scan_args = '-p-'
        elif scan_type == "Most Common Ports":
            scan_args = '-F'
        elif scan_type == "Specify a Port":
            port = self.specify_port_entry.text()
            scan_args = f'-p {port}'

        # Add additional flags if selected
        if self.flag_ss_cb.isChecked():
            scan_args += ' -sS'
        if self.flag_sv_cb.isChecked():
            scan_args += ' -sV'
        if self.flag_t4_cb.isChecked():
            scan_args += ' -T4'
        if self.flag_pn_cb.isChecked():
            scan_args += ' -Pn'
        if self.flag_a_cb.isChecked():
            scan_args += ' -A'
        # Add -T flag if selected
        for button in self.t_flags_group.buttons():
            if button.isChecked():
                scan_args += ' ' + button.text()

        # Initialize and start the scan thread
        self.scan_thread = ScanThread(ips, scan_args)
        self.scan_thread.update_progress.connect(self.update_progress)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.error_occurred.connect(self.show_error_message)
        self.scan_thread.result_acquired.connect(self.update_results_tree)
        self.scan_thread.start()

    def update_progress(self, value):
        self.progress.setValue(value)

    def scan_finished(self):
        self.progress.setVisible(False)
        QMessageBox.information(self, "Scan Complete", "The network scan has completed.")
        # Now that the scan is finished, save the results to a file if that option was selected.
        self.save_results_to_file(self.data)

    def show_error_message(self, message):
        QMessageBox.critical(self, "Error", message)

    def update_results_tree(self, data):
            """
            Updates the results tree widget with the given data.

            Args:
                data (dict): A dictionary containing the scan results.

            Returns:
                None
            """
            self.results_tree.clear()  # Clear the previous entries
            self.data = data  # Store the data as a class variable so we can use it later
            for host, ports in data.items():
                host_item = QTreeWidgetItem(self.results_tree)
                host_item.setText(0, f"Host: {host}")
                for port, details in ports.items():
                    port_item = QTreeWidgetItem(host_item)
                    port_item.setText(0, f"Port: {port}")
                    port_item.setText(1, f"State: {details['state']}")

                    # Initialize the ssh_hostkey_parent_item variable
                    ssh_hostkey_parent_item = None

                    # Check for details that are not 'state' or 'script'
                    for detail_key, detail_value in details.items():
                        if detail_key not in ['state', 'script', 'ssh-hostkey']:
                            if detail_value:
                                detail_item = QTreeWidgetItem(port_item)
                                detail_item.setText(0, str(detail_key).capitalize())
                                detail_item.setText(1, str(detail_value))

                    # Now handle 'ssh-hostkey' separately
                    if 'ssh-hostkey' in details:
                        ssh_hostkey_output = details['ssh-hostkey']
                        if ssh_hostkey_output:  # Check if there is any output to add
                            ssh_hostkey_parent_item = QTreeWidgetItem(port_item)
                            ssh_hostkey_parent_item.setText(0, "SSH-Hostkey")
                            for line in ssh_hostkey_output.split('\n'):
                                if line.strip():  # Make sure the line is not empty
                                    parts = line.strip().split(' ', 2)
                                    if len(parts) == 3:
                                        key_length, fingerprint, algorithm = parts
                                        # Create a new item for the algorithm
                                        algorithm_item = QTreeWidgetItem(ssh_hostkey_parent_item)
                                        algorithm_item.setText(0, f"Algorithm: {algorithm}")
                                        # Create a nested item under the algorithm for the key length
                                        key_length_item = QTreeWidgetItem(algorithm_item)
                                        key_length_item.setText(0, f"Key Length: ")
                                        key_length_item.setText(1, key_length)
                                        # Create a nested item under the algorithm for the fingerprint
                                        fingerprint_item = QTreeWidgetItem(algorithm_item)
                                        fingerprint_item.setText(0, "Fingerprint")
                                        fingerprint_item.setText(1, fingerprint)
            self.results_tree.expandAll()  # Optionally expand all items by default

    def save_results_to_file(self, data):
        """
        Saves the scan results to a file in the specified format.

        Args:
            data (dict): A dictionary containing the scan results.

        Returns:
            None
        """
        if not self.user_checked_save_to_file or not self.filename_to_save:
            return
        file_extension = os.path.splitext(self.filename_to_save)[1].lower()
        if file_extension == ".html":
            with open(self.filename_to_save, 'w') as file:
                # Create the HTML header
                file.write("<html><head><title>Scan Results</title></head><body>")
                file.write("<table border='1'>")

                # Create table headers
                file.write("<tr><th>Host</th><th>Port</th><th>State</th><th>Name</th><th>Product</th><th>Version</th><th>Extra</th><th>Scripts</tr></tr>")

                # Iterate through data and populate table rows
                for host, ports in data.items():
                    for port, details in ports.items():
                        file.write(f"<tr><td>{host}</td><td>{port}</td><td>{details['state']}</td><td>{details['name']}</td>")
                        file.write(f"<td>{details['product']}</td><td>{details['version']}</td><td>{details['extra']}</td>")
                        if 'ssh-hostkey' in details:
                            ssh_hostkey_info = details['ssh-hostkey'].replace('\n', '<br>')
                            file.write(f"<td>{ssh_hostkey_info}</td>")
                file.write("</tr>")
                file.write("</table></body></html>")
        elif file_extension == ".txt":
            with open(self.filename_to_save, 'w') as file:
                for host, ports in data.items():
                    file.write(f"Host: {host}\n")
                    for port, details in ports.items():
                        self.write_text_file(port, file, details)
        elif file_extension == ".json":
            with open(self.filename_to_save, 'w') as file:
                json.dump(data, file, indent=4)
        
    def write_text_file(self, port, file, details):
        """
        Writes details about a network port to a text file.

        Args:
            port (int): The port number.
            file (file): The file object to write to.
            details (dict): A dictionary containing details about the port.

        Returns:
            None
        """
        if port:
            file.write(f"  Port: {port}\n")
        else:
            file.write(f"  Port: N/A\n")
        if details['state']:
            file.write(f"    State: {details['state']}\n")
        if details['name']:
            file.write(f"    Name: {details['name']}\n")
        if details['product']:
            file.write(f"    Product: {details['product']}\n")
        if details['version']:
            file.write(f"    Version: {details['version']}\n")
        if details['cpe']:
            file.write(f"    CPE: {details['cpe']}\n")
        if details['extra']:
            file.write(f"    Extra: {details['extra']}\n")
        if 'script' in details:
            file.write(f"    Scripts:\n")
            for script, output in details['script'].items():
                if "ERROR" not in output:
                    file.write(f"      {script}: {output}\n")
                    
        if 'ssh-hostkey' in details:
            ssh_hostkey_data = details['ssh-hostkey'].split('\n')[1:]  # Skip the first line if it's empty or not needed
            for line in ssh_hostkey_data:
                file.write(f"    SSH-Hostkey:\n")
                if line.strip():
                    parts = [part.strip() for part in line.split()]
                    if len(parts) >= 3:
                        key_length = parts[0]
                        fingerprint = parts[1]
                        algorithm = ' '.join(parts[2:])
                        file.write(f"      Key Length: {key_length}\n")
                        file.write(f"      Algorithm: {algorithm}\n")
                        file.write(f"      Fingerprint: {fingerprint}\n")

    def toggle_net_discovery(self, checked):
        """
        Toggles the network discovery feature on or off.

        Args:
            checked (bool): Whether the network discovery feature is checked or not.
        """
        if checked:
            self.host_entry.setDisabled(True)
            self.file_button.setDisabled(True)
        else:
            self.host_entry.setDisabled(False)
            self.file_button.setDisabled(False)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NmapGUI()
    window.show()
    sys.exit(app.exec_())
