from collections import defaultdict
import csv
import json

class Firewall(object):
	def __init__(self,path):
		"""Initialize the firewall rulset from the CSV entries
		"""
		# firewall = {
		#				ip: {
		#					port/port_range: [(direction,protocol)]
		#				}
		#			}

		self.firewall = defaultdict(lambda : defaultdict(set))
		with open(path, 'rb') as csvfile:
			spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
			spamreader =['inbound,tcp,80,192.168.1.2', 'outbound,tcp,10000-20000,192.168.10.11','inbound,udp,53,192.168.1.1-192.168.2.5','outbound,udp,1000-2000,52.12.48.92']
			for line in spamreader:
				# Extract fields from CSV
				row = line.split(",")
				direction = row[0]
				protocol = row[1]
				port = row[2]
				ip_range = row[3]

				if '-' in ip_range:
					# If IP range, get all IPs in the range
					parts = ip_range.split('-')
					for ip in self.ipRange(parts[0], parts[1]):
						self.firewall[ip][port].add((direction,protocol))
				else:
					# Else use the single IP
					self.firewall[ip_range][port].add((direction,protocol))

		print(json.dumps(self.firewall), indent=4)

	def ipRange(self,start_ip, end_ip):
		"""Return all IPs within start and end
		"""

		start = list(map(int, start_ip.split(".")))
		end = list(map(int, end_ip.split(".")))
		temp = start
		ip_range = []

		ip_range.append(start_ip)
		while temp != end:
		  start[3] += 1
		  for i in (3, 2, 1):
		     if temp[i] == 256:
		        temp[i] = 0
		        temp[i-1] += 1
		  ip_range.append(".".join(map(str, temp)))    
		  
		return ip_range

	def allow(self,test_input):
		"""Method to allow/disallow based on firewall ruleset
		"""
		# Extract fields of input
		direction = test_input[0]
		protocol = test_input[1]
		port = test_input[2]
		ip = test_input[3]

		for rule in self.firewall:
			if rule == ip:
				# If IP exists in the ruleset
				for port_range in self.firewall[rule]:
					if '-' in port_range:
						# To check against port ranges
						start_port = port_range.split("-")[0]
						end_port = port_range.split("-")[1]
						if int(start_port) <= int(port) <= int(end_port):
							# If port lies within the range
							if (direction,protocol) in self.firewall[rule][port_range]:
								return True

					elif port == int(port_range):
						# To check for a single port
						if (direction,protocol) in self.firewall[rule][port_range]:
								return True
		return False


fw = Firewall("input.xlsx")
test_inputs = [("inbound", "tcp", 80, "192.168.1.2"), ("inbound", "udp", 53, "192.168.2.1"), ("outbound", "tcp", 10234, "192.168.10.11"), ("inbound", "tcp", 81, "192.168.1.2"),("inbound", "udp", 24, "52.12.48.92")]
for test in test_inputs:
	print(fw.allow(test))

