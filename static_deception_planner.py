from mininet.net import Containernet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
import sys
import ipaddress
import random
import requests # CREATE INTENTS and TRAFFIC FLOW
import json

setLogLevel('info')
                                  
type_of_attack = sys.argv[1]
attacker_ip = sys.argv[2] 
attack_details = sys.argv[3] 
threat_actor = sys.argv[4]
cve = sys.argv[5]   

playbook_mapping = { # by having this object, this can be stored anywhere and imported by this script (e.g., json in web server, other script, etc.)
    (True, True, False, False, False): "1",
    (True, True, True, False, False): "2",
    (True, True, True, True, False): "3",
    (True, True, True, True, True): "4"
}

playbook = playbook_mapping.get((bool(type_of_attack),bool(attacker_ip),bool(attack_details), bool(threat_actor), bool(cve)), "default")
    
used_ips_addresses = set()
used_mac_addresses = set()

hosts_ips_macs=[]

def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def get_random_ip_within_network(attacker_ip_address): 
    
    if '/' not in attacker_ip_address:
        attacker_ip_address += '/24'
    
    ip_network = ipaddress.IPv4Network(attacker_ip_address, strict=False)
        
    if ip_network.num_addresses <= 2: 
        raise ValueError("IP network must have at least three hosts")

    while True:
        random_ip = str(ipaddress.IPv4Address(random.randint(int(ip_network.network_address)+1, int(ip_network.broadcast_address)-1)))
        if random_ip not in used_ips_addresses:
            used_ips_addresses.add(random_ip)
            return random_ip
        elif len(used_ips_addresses) == ip_network.num_addresses - 2:
            used_ips_addresses.clear()

def get_random_mac():
    
    mac = ":".join(["{:02x}".format(random.randint(0, 255)) for _ in range(6)])

    while mac in used_mac_addresses:
        mac = ":".join(["{:02x}".format(random.randint(0, 255)) for _ in range(6)])

    used_mac_addresses.add(mac)

    return mac

def define_hosts(attack_type,attacker_ip,attack_details,threat_actor,cve,playbook):  ## HOSTS CAN´T HAVE THE SAME NAME OF A ALREADY DEPLOYED PLAN

    parse_json = load_json(f'./plans_config/playbook{playbook}/hosts_plans_playbook{playbook}.json') 
  
    specific_attacks_hosts = parse_json.get(f"{attack_type}|{attack_details}|{threat_actor}|{cve}") 

    if specific_attacks_hosts:
        for host in specific_attacks_hosts:
            random_ip = get_random_ip_within_network(attacker_ip)
            random_mac = get_random_mac()
            host['ip'] = random_ip
            host['mac'] = random_mac

            host = {"name":host['name'], "ip": random_ip, "mac": random_mac}
            hosts_ips_macs.append(host)

        return specific_attacks_hosts
    else:
        return "No attack corresponding given parameters was found."


def define_network_switches(attack_type,attacker_ip,attack_details,threat_actor,cve,playbook):  ## SWITCHES CAN´T HAVE THE SAME NAME OF A ALREADY DEPLOYED PLAN
     
    parse_json = load_json(f'./plans_config/playbook{playbook}/switches_plans_playbook{playbook}.json')

    specific_attacks_switches = parse_json.get(f"{attack_type}|{attack_details}|{threat_actor}|{cve}") 
    
    if specific_attacks_switches:
        return specific_attacks_switches
    else:
        return "No attack corresponding given parameters was found."
    

def define_network_links(net_hosts,network_switches,attack_type,attacker_ip,attack_details,threat_actor,cve,playbook):

    parse_json = load_json(f'./plans_config/playbook{playbook}/links_plans_playbook{playbook}.json')

    specific_attacks_links = parse_json.get(f"{attack_type}|{attack_details}|{threat_actor}|{cve}") 
    
    if specific_attacks_links:
        for link in specific_attacks_links:
            if link["device1"][0] == "s":
                if link["device1"] in network_switches:
                    link["device1"] = network_switches[link["device1"]]
            elif link["device1"][0] == "h":
                if link["device1"] in net_hosts:
                    link["device1"] = net_hosts[link["device1"]]
  
            if link["device2"][0] == "s":
                if link["device2"] in network_switches:
                    link["device2"] = network_switches[link["device2"]]
            elif link["device2"][0] == "h":
                if link["device2"] in net_hosts:
                    link["device2"] = net_hosts[link["device2"]]        

        return specific_attacks_links
    else:
        return "No attack corresponding given parameters was found."

def define_network_sdn_controllers(attack_type,attacker_ip,attack_details,threat_actor,cve,playbook):
     
    parse_json = load_json(f'./plans_config/playbook{playbook}/controllers_plans_playbook{playbook}.json')

    specific_attacks_controllers = parse_json.get(f"{attack_type}|{attack_details}|{threat_actor}|{cve}") 

    if specific_attacks_controllers:
        return specific_attacks_controllers
    else:
        return "No attack corresponding given parameters was found."

def define_host_cmds(net_hosts,attack_type,attacker_ip,attack_details,threat_actor,cve,playbook):
     
    parse_json = load_json(f'./plans_config/playbook{playbook}/hostcommands_plans_playbook{playbook}.json')
    
    specific_attacks_commands = parse_json.get(f"{attack_type}|{attack_details}|{threat_actor}|{cve}") 
  
    if len(specific_attacks_commands) > 0:
        for command in specific_attacks_commands:
            for host in net_hosts:
            	if list(host.keys())[0] == command["host"]:
                    if "ip" in command["cmd"]:
                        host_ip=""
                        for obj in hosts_ips_macs:
                                if obj.get("name") == command["host"]:
                                    host_ip=obj.get("ip")
                        command["cmd"] = command["cmd"].replace("ip", host_ip)
                    host[list(host.keys())[0]].cmd(command["cmd"])
                   
    return specific_attacks_commands    
    
def define_network_traffic_policies(controllers,attack_type,attacker_ip,attack_details,threat_actor,cve,playbook): # PASSAR sdn_controllers EM VEZ DE sdn_network_controllers
   
    parse_json = load_json(f'./plans_config/playbook{playbook}/intents_plans_playbook{playbook}.json')
    specific_attacks_intents = parse_json.get(f"{attack_type}|{attack_details}|{threat_actor}|{cve}") 
   
    if len(specific_attacks_intents) > 0: 
        
        for controller in controllers:
                
            controller_ip = controller["ip"]
            url = f"http://{controller_ip}:8181/onos/v1/intents"

            headers = {'Accept' : 'application/json'}
            
            for intent in specific_attacks_intents:
    
                for criterion in intent["selector"]["criteria"]: # replace host name with already random generated IP for host
                    if criterion.get("type") == "IPV4_SRC" or criterion.get("type") == "IPV4_DST":
                        random_ip_host =""
                        for obj in hosts_ips_macs:
                            if obj.get("name") == criterion.get("ip") :
                                random_ip_host =  obj.get("ip")
                        criterion["ip"] = random_ip_host+"/32"
                        

                response = requests.post(url, headers=headers, data=json.dumps(intent), auth=('onos','rocks'))
                print(f"Response from SDN Controller ({controller_ip}) for intent: ", response)

    else:
        print("No traffic policies were assigned.")

def define_network_traffic_flows(controllers,attack_type,attacker_ip,attack_details,threat_actor,cve,playbook): # PASSAR sdn_controllers EM VEZ DE sdn_network_controllers
   
    parse_json = load_json(f'./plans_config/playbook{playbook}/flows_plans_playbook{playbook}.json')
    specific_attacks_flows= parse_json.get(f"{attack_type}|{attack_details}|{threat_actor}|{cve}") 
   
    if len(specific_attacks_flows) > 0: 
        
        for controller in controllers:
                
            controller_ip = controller["ip"]
            appId = specific_attacks_flows[0].get("appId")
            url = f"http://{controller_ip}:8181/onos/v1/flows?appId={appId}"

            headers = {'Accept' : 'application/json'}
            
            for flow in specific_attacks_flows:

                for flow in flow["flows"]:
                    for criterion in flow["selector"]["criteria"]: # replace host name with already random generated IP for host
                         if criterion.get("type") == "IPV4_SRC" or criterion.get("type") == "IPV4_DST":
                            random_ip_host =""
                            for obj in hosts_ips_macs:
                                if obj.get("name") == criterion.get("ip") :
                                 random_ip_host =  obj.get("ip")
                            criterion["ip"] = random_ip_host+"/32"

                if "appId" in flow:
                    del flow["appId"]  # remove the 'appId' from the flow obj to not be sent on the body

            for flow in specific_attacks_flows:
                response = requests.post(url, headers=headers, data=json.dumps(flow), auth=('onos','rocks'))
                print(f"Response from SDN Controller ({controller_ip}) for flow: ", response)

    else:
        print("No traffic flows were assigned.")
        

# BUILDING THE NETWORK

net = Containernet()

info('*** Adding Deception Grid SDN Controller ***\n')

sdn_controllers = define_network_sdn_controllers(type_of_attack,attacker_ip,attack_details,threat_actor,cve,playbook)
sdn_network_controllers =[]

for controller in sdn_controllers:
    c = RemoteController( controller['name'] ,  ip = controller['ip'], port=controller['port'])
    sdn_network_controllers.append(net.addController(c))

info('*** Adding Deception Grid Hosts ***\n')

hosts = define_hosts(type_of_attack,attacker_ip,attack_details,threat_actor,cve,playbook)

net_hosts = []

for host in hosts: # Check other possibilities of properties 

    if(host['isDocker'] == 1):  
        if all(key in host for key in ('ports', 'port_bindings', 'environment')):
            net_hosts.append({ host['name'] : net.addDocker(host['name'],ip=host['ip'],mac=host['mac'],dimage=host['dimage'], ports=host['ports'],port_bindings=host['port_bindings'], environment=host['environment'])})
        else:
            if all(key in host for key in ('ports', 'port_bindings')):
                net_hosts.append({ host['name'] : net.addDocker(host['name'],ip=host['ip'],mac=host['mac'],dimage=host['dimage'], ports=host['ports'],port_bindings=host['port_bindings'])})
            
            elif 'environment' in host:
                net_hosts.append({ host['name'] : net.addDocker(host['name'],ip=host['ip'],mac=host['mac'],dimage=host['dimage'], environment=host['environment'])})
            else:
                net_hosts.append({ host['name'] : net.addDocker(host['name'],ip=host['ip'],mac=host['mac'],dimage=host['dimage'])})
    else:
        net_hosts.append({ host['name'] :net.addHost(host['name'],ip=host['ip'])})

info('*** Adding Deception Grid Switches ***\n')

switches = define_network_switches(type_of_attack,attacker_ip,attack_details,threat_actor,cve,playbook)
network_switches={}

for i in switches:
      network_switches[i] = net.addSwitch(i) ## SWITCHES CAN´T HAVE THE SAME NAME OF A ALREADY DEPLOYED PLAN


info('*** Creating Deception Grid Links ***\n')

links = define_network_links(net_hosts,network_switches,type_of_attack,attacker_ip,attack_details,threat_actor,cve,playbook)
network_links=[]


for link in links:
     network_links.append(net.addLink(link['device1'],link['device2'],link['port1'],link['port2']))


info('*** Starting Deception Grid ***\n')

net.start()

net.pingAll() # make hosts visible to SDN controller due to reactive forwarding (automatic discovery)

info('*** Injecting Commands in Hosts ***\n')

injected_comands = define_host_cmds(net_hosts,type_of_attack,attacker_ip,attack_details,threat_actor,cve,playbook)

if len(injected_comands) > 0:
    for command in injected_comands:
        print(command)
else:
    print("No commands were assigned.")

info('*** Creating Deception Grid Traffic Policies ***\n')

define_network_traffic_policies(sdn_controllers,type_of_attack,attacker_ip,attack_details,threat_actor,cve,playbook)

info('*** Creating Deception Grid Traffic Flows ***\n')

define_network_traffic_flows(sdn_controllers,type_of_attack,attacker_ip,attack_details,threat_actor,cve,playbook)

info('*** Running CLI ***\n')

CLI(net)
net.stop()
