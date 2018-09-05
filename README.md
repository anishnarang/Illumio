# Solution overview:
I made use of set and dictionary datatypes as much as possible as the access time for these is O(1). I build the firewall ruleset as a dictionary of dictionaries with the following structure:

		firewall = {
					ip1: {
							port/port_range: [(direction,protocol),..],
							port/port_range: [(direction,protocol),..],
						},
					ip2: {
							port/port_range: [(direction,protocol),..],
							port/port_range: [(direction,protocol),..],
						},
					}

Each IP in the input CSV file is used as the top level hash key as it the most differentiable field compared to the other fields. 
Each IP has a dictionary with key as port/port_range, and finally a list of tuples that indicate the direction and protocol allowed for that port and that IP.

If the input IP is a range, all the IPs within the range are expanded and stored as a key. Although this would require more space, this is done because a later entry may have an IP within that range with different ports. Also, while checking whether to allow/disallow a test input, we can check if the IP is in the keys of the top dictionary and return False immediately if it is not present.

# Input:
I created a firewall rulset using the sample entries given in the PDF.
inbound	tcp	80	192.168.1.2
outboud	tcp	10000-20000	192.168.10.11
inbound	udp	53	192.168.1.1-192.168.2.5
outboud	udp	1000-2000	52.12.48.92

# Testing:
Since the IP is the most differentiable field and is at the top level, I check if the IP is in the dictionary.
If no, disallow the rule.
If yes, move on to check if the port is allowed.
If no, disallow the rule.
If yes, move on to check if the tuple (direction, protocol) is allowed for that IP and port.
If yes, allow the rule.
If no, disallow the rule.

I tested the script with the tests in the PDF.
test_inputs = [("inbound", "tcp", 80, "192.168.1.2"), ("inbound", "udp", 53, "192.168.2.1"), ("outbound", "tcp", 10234, "192.168.10.11"), ("inbound", "tcp", 81, "192.168.1.2"),("inbound", "udp", 24, "52.12.48.92")]

# Teams I am interested in:
Data and Platform teams
1. New College Graduate, 2019, Software Engineer, Data
2. New College Graduate, 2019, Data Visualization
3. New College Graduate, 2019, Back-end Software Engineer, Policy

