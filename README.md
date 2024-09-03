# First-strike-
First Strike Intrusion Detection system with machine learning analysis. 

UPDATE 3/09:  CODE SHOWS OUTPUTS FOR: 
Source IP, Destination IP, Source Mac, Destination MAC, Protocols. 
Threat Detection Incorporated through a Github library of malicious attacks and IOCs. 


Project Overview: The project as a whole is an anomaly based IDS. We have packet sniffing through python that gathers data such as IP address source and destination, MAC address source and destination, port number, and DNS query. Machine learning will be incorporated in order to match the information of the packets to detect any anomalies. Machine learning will be done through an intrusion data set (a CSV). Data will be added to the CSV through the sniffing application with its current contents in order to do the training. This model is then used to aid the sniffing application as mentioned previously regarding detecting anomalies. This information is gathered into data (report) which will be visualised in order to provide a comprehensive understanding of where the packets are coming from, what is malicious and what is potentially malicious (anomalies).


Readings: https://www.sciencedirect.com/science/article/pii/S2665963822001300
Github: https://github.com/SoftwareImpacts/SIMPAC-2022-260
Github for data analysis and ML-IDS: https://github.com/Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning/blob/main/Tree-based_IDS_GlobeCom19.ipynb


DESCRIPTION: This code provides tools for capturing and analyzing network packets. It includes functions to check if an IP address is public, resolve IP addresses to domain names, and identify processes or devices associated with public IPs. It analyzes packets to extract details like IPs, MAC addresses, protocols, and DNS queries, and checks for malicious IPs. The GUI allows users to start and stop packet sniffing, display packet information, clear data, and generate reports summarizing the captured data.


Current actions by code:

is_public_ip(ip_address)

Purpose: Checks if a given IP address is within a public IP range.
Details: Converts the IP address to an integer and compares it against predefined public IP ranges. Returns True if the IP is public, otherwise False.
resolve_ip_to_domain(ip_address)

Purpose: Resolves an IP address to its domain name if it's a public IP.
Details: Uses the socket.gethostbyaddr function to find the domain name associated with the IP. Caches the result for future lookups. Returns "N/A" if the resolution fails or if the IP is not public.
find_process_by_ip(ip_address)

Purpose: Finds the process associated with a given public IP address.
Details: Iterates through network connections and checks if the IP matches the remote IP of any connection. If found, retrieves the process name, PID, and executable path using psutil. Returns "Unknown" and "N/A" if no matching process is found or access is denied.
identify_device(ip_address)

Purpose: Identifies the device or network based on the IP address.
Details: If the IP is public, attempts to resolve the IP to a device name. Returns "Unknown Device" if the resolution fails or if the IP is not public.
analyze_packet(packet)

Purpose: Analyzes a packet to extract and return relevant information.
Details: Checks if the packet contains IP layers and if the IP addresses are public. Extracts source and destination MAC addresses, IP addresses, protocols, and ports. Resolves DNS queries and identifies devices based on IP addresses. Checks if the packet involves any known malicious IPs. Returns a dictionary with packet information.
display_packet(packet)

Purpose: Formats and displays packet information in the GUI.
Details: Uses analyze_packet to get packet details and formats them into a readable string. Adds this string to a queue for thread-safe GUI updates.
start_sniffing()

Purpose: Starts packet sniffing and creates a background thread to capture packets.
Details: Sets a global flag to indicate sniffing has started. Creates and starts a thread that uses scapy.sniff to capture packets and processes them with display_packet. Calls process_queue periodically to update the GUI.
stop_sniffing()

Purpose: Stops packet sniffing.
Details: Sets a global flag to indicate sniffing has stopped. Adds a message to the GUI to indicate the stopping of sniffing.
process_queue()

Purpose: Processes and updates the GUI with packet information from the queue.
Details: Retrieves and displays packet information from the queue in the GUI. Continues to process the queue if sniffing is still active.
clear_packet_data()

Purpose: Clears all packet data from the GUI.
Details: Deletes the contents of the scrolled text widget used for displaying packet data.
generate_report()

Purpose: Generates and saves a report of the captured packet data.
Details: Stops sniffing, creates a report from the packet data displayed in the GUI, and saves the report to a file on the desktop. Filters out "N/A" fields and excludes packets with only basic information. Updates the GUI with the report details and saves the report to a file.

System requirements and libraries to be installed for code to work (PLS INSERT NEW LIBRARIES IN HERE). 

1. os: This is a standard Python library for interacting with the operating system.
2. tkinter: This is a standard Python library for creating GUI applications.
3. threading: This is a standard Python library for creating and managing threads.
4. queue: This is a standard Python library for working with thread-safe queues.
5. Datetime: This is a standard Python library for handling dates and times.
6. socket: This is a standard Python library for network communication.
8. psutil: This library provides system and process utilities. Install it via pip using pip install psutil.
9. scapy: This is a powerful Python library for packet manipulation and analysis. If it's not already installed, it will be installed automatically by the code if needed.
10. Change line 415  (desktop_path = "C:/Users/YOURDEVICENAME/OneDrive/Desktop") to the name of your device to add files to your desktop. 
