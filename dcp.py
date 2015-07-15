import argparse


from util import *
from protocol import *


params = {
    "name": PNDCPBlock.NAME_OF_STATION,
    "ip": PNDCPBlock.IP_ADDRESS
}

def get_param(s, src, target, param):
    dst = s2mac(target)
    
    if param not in params.keys():
        return
    
    param = params[param]
    
    block = PNDCPBlockRequest(param[0], param[1], 0, bytes())
    dcp   = PNDCPHeader(0xfefd, PNDCPHeader.GET, PNDCPHeader.REQUEST, 0x012345, 0, 2, block)
    eth   = EthernetVLANHeader(dst, src, 0x8100, 0, PNDCPHeader.ETHER_TYPE, dcp)
    
    s.send(bytes(eth))
    
    recv.read_response(s, src)

def set_param(s, src, target, param, value):
    dst = s2mac(target)
    
    if param not in params.keys():
        return
    
    param = params[param]
    
    block = PNDCPBlockRequest(param[0], param[1], len(value) + 2, bytes([0x00, 0x00]) + bytes(value, encoding='ascii'))
    dcp   = PNDCPHeader(0xfefd, PNDCPHeader.SET, PNDCPHeader.REQUEST, 0x012345, 0, len(value) + 6 + (1 if len(value) % 2 == 1 else 0), block)
    eth   = EthernetVLANHeader(dst, src, 0x8100, 0, PNDCPHeader.ETHER_TYPE, dcp)
    
    s.send(bytes(eth))


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


def read_response(s, my_mac, want=None, debug=False):
    ret = []
    found = []
    try:
        with timeout(20):
            while s is not None:
                data = s.recv(1522)
                
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
                
                while length > 6:
                    block = PNDCPBlock(blocks)
                    if want is None or (block.option, block.suboption) in want:
                        found.append((block.option, block.suboption))
                        ret.append(block)
                    
                    block_len = block.length
                    if debug:
                        if (block.option, block.suboption) == PNDCPBlock.NAME_OF_STATION:
                            print("Name of Station: %s" % block.payload)
                        elif (block.option, block.suboption) == PNDCPBlock.IP_ADDRESS:
                            print(str(block.parse_ip()))
                    
                    # Padding:
                    if block_len % 2 == 1:
                        block_len += 1
                    
                    # geparsten Block entfernen
                    blocks = blocks[block_len+4:]
                    length -= 4 + block_len
                
                if want is not None and sorted(found) == sorted(want):
                    break

    except TimeoutError:
        pass

    return ret
