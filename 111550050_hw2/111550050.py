# -*- coding: utf-8 -*-
from setting import get_hosts, get_switches, get_links, get_ip, get_mac
from enum import Enum
    
class PacketType(Enum):
    ICMP_REQUEST = 0
    ICMP_RESPONSE = 1
    ARP_REQEUST = 2
    ARP_RESPONSE = 3
    

class Host:
    def __init__(self, name: str, ip: str, mac: str):
        self.name = name
        self.ip = ip
        self.mac = mac 
        self.port_to = None 
        self.arp_table = dict() # maps IP addresses to MAC addresses
        
    def add(self, node):
        self.port_to = node
        
    def show_table(self):
        for i in self.arp_table:
            print(f'{i} : {self.arp_table[i]}')
            
    def clear(self):
        self.arp_table.clear()
        
    def update_arp(self, ip: str, mac: str):
        self.arp_table[ip] = mac        
    
    def arp_request(self, target_ip: str):
        self.send(PacketType.ARP_REQEUST, 'ffff', src_ip=self.ip, ip=target_ip)
        return target_ip not in self.arp_table
    
    def ping(self, dst_ip: str, isRequest = True):
        ptype = PacketType.ICMP_REQUEST if isRequest else PacketType.ICMP_RESPONSE
    
        if(dst_ip not in self.arp_table):
            if self.arp_request(dst_ip) == 1:
                return 1
        
        self.send(ptype, self.arp_table[dst_ip], src_ip=self.ip, dst_ip=dst_ip)
        return 0
    
    def handle_packet(self, packet_type: PacketType, src_mac: str, src_name: str, dst_mac: str, **kwargs):
        if packet_type == PacketType.ICMP_REQUEST:
            if kwargs['dst_ip'] != self.ip: return 1
            self.ping(kwargs['src_ip'], False)
            
        elif packet_type == PacketType.ICMP_RESPONSE:
            pass
        
        elif packet_type == PacketType.ARP_REQEUST:            
            if(kwargs['ip'] != self.ip): return 1
            self.update_arp(kwargs['src_ip'], src_mac)
            self.send(PacketType.ARP_RESPONSE, src_mac, src_ip=kwargs['src_ip'], ip=self.ip, mac=self.mac)
            
        elif packet_type == PacketType.ARP_RESPONSE:
            if(kwargs['src_ip'] != self.ip): return 1
            self.update_arp(kwargs['ip'], kwargs['mac'])
            
        else:
            return 1

    def send(self, packet_type: PacketType, dst_mac: str, **kwargs):        
        node = self.port_to
        node.handle_packet(packet_type, self.mac, self.name, dst_mac, **kwargs)        

class Switch:
    def __init__(self, name, port_n):
        self.name = name
        self.mac_table = dict() # maps MAC addresses to port numbers
        self.port_n = port_n # number of ports on this switch
        self.port_to = list()
        
    def add(self, node): # link with other hosts or switches
        self.port_to.append(node)
        
    def show_table(self):
        for m in self.mac_table:
            print(f'{m} : {self.mac_table[m]}')
            
    def clear(self):
        self.mac_table.clear()
        
    def update_mac(self, mac: str, port: int):
        self.mac_table[mac] = port
        
    def send(self, packet_type: PacketType, src_mac: str, dst_mac: str, in_port: int, **kwargs):
        if dst_mac in self.mac_table and dst_mac != 'ffff':
            port_idx = self.mac_table[dst_mac] 
            node = self.port_to[port_idx] 
            node.handle_packet(packet_type, src_mac, self.name, dst_mac, **kwargs)
        else:
            for i in range(self.port_n):
                if i == in_port: continue
                self.port_to[i].handle_packet(packet_type, src_mac, self.name, dst_mac, **kwargs)
        
        
    def handle_packet(self, packet_type: PacketType, src_mac: str, src_name: str, dst_mac: str, **kwargs):
        # Find out incoming port. This should be done by hardware in reality.
        in_port = -1
        for i in range(self.port_n):
            if self.port_to[i].name == src_name:
                in_port = i
                break        
        if in_port == -1: return 1
        
        # Main function
        self.update_mac(src_mac, in_port)
        self.send(packet_type, src_mac, dst_mac, in_port, **kwargs)
        

def add_link(tmp1, tmp2): # create a link between two nodes
    if tmp1 in host_dict:
        node1 = host_dict[tmp1]
    else:
        node1 =  switch_dict[tmp1]
    if tmp2 in host_dict:
        node2 = host_dict[tmp2]
    else:
        node2 = switch_dict[tmp2]
    node1.add(node2)
    node2.add(node1)

def set_topology():
    global host_dict, switch_dict
    hostlist = get_hosts().split(' ')
    switchlist = get_switches().split(' ')
    link_command = get_links()
    ip_dic = get_ip()
    mac_dic = get_mac()
    
    host_dict = dict() # maps host names to host objects
    switch_dict = dict() # maps switch names to switch objects
    
    for h in hostlist:
        host_dict[h] = Host(h, ip_dic[h], mac_dic[h])
    for s in switchlist:
        switch_dict[s] = Switch(s, len(link_command.split(s))-1)
    for l in link_command.split(' '):
        [n0, n1] = l.split(',')
        add_link(n0, n1)

def ping(tmp1, tmp2): # initiate a ping between two hosts
    global host_dict, switch_dict
    if tmp1 in host_dict and tmp2 in host_dict : 
        node1 = host_dict[tmp1]
        node2 = host_dict[tmp2]
        node1.ping(node2.ip)
    else : 
        return 1 # wrong 
    return 0 # success 


def show_table(tmp): # display the ARP or MAC table of a node
    if tmp == 'all_hosts':
        print(f'ip : mac')
        for h in host_dict:
            print(f'---------------{h}:')
            host_dict[h].show_table()
        print()
    elif tmp == 'all_switches':
        print(f'mac : port')
        for s in switch_dict:
            print(f'---------------{s}:')
            switch_dict[s].show_table()
        print()
    elif tmp in host_dict:
        print(f'ip : mac\n---------------{tmp}')
        host_dict[tmp].show_table()
    elif tmp in switch_dict:
        print(f'mac : port\n---------------{tmp}')
        switch_dict[tmp].show_table()
    else:
        return 1
    return 0


def clear(tmp):
    wrong = 0
    if tmp in host_dict:
        host_dict[tmp].clear()
    elif tmp in switch_dict:
        switch_dict[tmp].clear()
    else:
        wrong = 1
    return wrong


def run_net():
    while(1):
        wrong = 0 
        command_line = input(">> ")
        command_list = command_line.strip().split(' ')
        
        if command_line.strip() =='exit':
            return 0
        if len(command_list) == 2 : 
            if command_list[0] == 'show_table':
                wrong = show_table(command_list[1])
            elif command_list[0] == 'clear' :
                wrong = clear(command_list[1])
            else :
                wrong = 1 
        elif len(command_list) == 3 and command_list[1] == 'ping' :
            wrong = ping(command_list[0], command_list[2])
        else : 
            wrong = 1
        if wrong == 1:
            print('a wrong command')

    
def main():
    set_topology()
    run_net()


if __name__ == '__main__':
    main()