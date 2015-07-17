import argparse, time


from util import *
from protocol import *


params = {
    "name": PNDCPBlock.NAME_OF_STATION,
    "ip": PNDCPBlock.IP_ADDRESS
}


class DCPDeviceDescription:
    def __init__(self, mac, blocks):
        self.mac = mac2s(mac)
        self.name = blocks[PNDCPBlock.NAME_OF_STATION].decode()
        self.ip = s2ip(blocks[PNDCPBlock.IP_ADDRESS][0:4])
        self.netmask = s2ip(blocks[PNDCPBlock.IP_ADDRESS][4:8])
        self.gateway = s2ip(blocks[PNDCPBlock.IP_ADDRESS][8:12])
        self.vendorHigh, self.vendorLow, self.devHigh, self.devLow = unpack(">BBBB", blocks[PNDCPBlock.DEVICE_ID][0:4])


def get_param(s, src, target, param):
    dst = s2mac(target)
    
    if param not in params.keys():
        return
    
    param = params[param]
    
    block = PNDCPBlockRequest(param[0], param[1], 0, bytes())
    dcp   = PNDCPHeader(0xfefd, PNDCPHeader.GET, PNDCPHeader.REQUEST, 0x012345, 0, 2, block)
    eth   = EthernetVLANHeader(dst, src, 0x8100, 0, PNDCPHeader.ETHER_TYPE, dcp)
    
    s.send(bytes(eth))
    
    return list(read_response(s, src, once=True).values())[0][param]

def set_param(s, src, target, param, value):
    dst = s2mac(target)
    
    if param not in params.keys():
        return
    
    param = params[param]
    
    block = PNDCPBlockRequest(param[0], param[1], len(value) + 2, bytes([0x00, 0x00]) + bytes(value, encoding='ascii'))
    dcp   = PNDCPHeader(0xfefd, PNDCPHeader.SET, PNDCPHeader.REQUEST, 0x012345, 0, len(value) + 6 + (1 if len(value) % 2 == 1 else 0), block)
    eth   = EthernetVLANHeader(dst, src, 0x8100, 0, PNDCPHeader.ETHER_TYPE, dcp)
    
    s.send(bytes(eth))
    
    # ignore response
    s.recv(1522)
    
    time.sleep(2)


def send_discover(s, src):
    
    block = PNDCPBlockRequest(0xFF, 0xFF, 0, bytes())
    dcp   = PNDCPHeader(0xfefe, PNDCPHeader.IDENTIFY, PNDCPHeader.REQUEST, 0x012345, 0, len(block), payload=block)
    eth   = EthernetVLANHeader(s2mac("01:0e:cf:00:00:00"), src, 0x8100, 0, PNDCPHeader.ETHER_TYPE, payload=dcp)
    
    s.send(bytes(eth))


def send_request(s, src, t, value):
    
    block = PNDCPBlockRequest(t[0], t[1], len(value), bytes(value))
    dcp   = PNDCPHeader(0xfefe, PNDCPHeader.IDENTIFY, PNDCPHeader.REQUEST, 0x012345, 0, len(block), block)
    eth   = EthernetVLANHeader(s2mac("01:0e:cf:00:00:00"), src, 0x8100, 0, PNDCPHeader.ETHER_TYPE, dcp)
    
    s.send(bytes(eth))


def read_response(s, my_mac, to=20, once=False, debug=False):
    ret = {}
    found = []
    s.settimeout(2)
    try:
        with max_timeout(to) as t:
            while True:
                if t.timed_out:
                    break
                try:
                    data = s.recv(1522)
                except timeout:
                    continue
                
                # nur Ethernet Pakete an uns und vom Ethertype Profinet
                eth = EthernetHeader(data)
                if eth.dst != my_mac or eth.type != PNDCPHeader.ETHER_TYPE:
                    continue
                debug and print("MAC address:", mac2s(eth.src))
                
                # nur DCP Identify Responses
                pro = PNDCPHeader(eth.payload)
                if not (pro.service_type == PNDCPHeader.RESPONSE):
                    continue
                
                # Blöcke der Response parsen
                blocks = pro.payload
                length = pro.length
                parsed = {}
                
                while length > 6:
                    block = PNDCPBlock(blocks)
                    blockoption = (block.option, block.suboption)
                    parsed[blockoption] = block.payload
                    
                    block_len = block.length
                    if blockoption == PNDCPBlock.NAME_OF_STATION:
                        debug and print("Name of Station: %s" % block.payload)
                        parsed["name"] = block.payload
                    elif blockoption == PNDCPBlock.IP_ADDRESS:
                        debug and print(str(block.parse_ip()))
                        parsed["ip"] = s2ip(block.payload[0:4])
                    elif blockoption == PNDCPBlock.DEVICE_ID:
                        parsed["devId"] = block.payload
                    
                    # Padding:
                    if block_len % 2 == 1:
                        block_len += 1
                    
                    # geparsten Block entfernen
                    blocks = blocks[block_len+4:]
                    length -= 4 + block_len

                ret[eth.src] = parsed
                
                if once:
                    break

    except TimeoutError:
        pass

    return ret
