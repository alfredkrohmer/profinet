from struct import unpack
from socket import MSG_WAITALL

from util import *
from protocol import *

import dcp


def get_station_info(s, src, name):
    dcp.send_request(s, src, PNDCPBlock.NAME_OF_STATION, bytes(name, 'utf-8'))
    ret = dcp.read_response(s, src, want=(PNDCPBlock.IP_ADDRESS, PNDCPBlock.DEVICE_ID))

    ip = ""
    vendorHigh = vendorLow = devHigh = devLow = 0
    for block in ret:
        if (block.option, block.suboption) == PNDCPBlock.IP_ADDRESS:
            ip = s2ip(block.payload[0:4])
        if (block.option, block.suboption) == PNDCPBlock.DEVICE_ID:
            vendorHigh, vendorLow, devHigh, devLow = unpack(">BBBB", block.payload[0:4])
    
    return ip, vendorHigh, vendorLow, devHigh, devLow


class RPCCon:
    def __init__(self, ip, vendorHigh, vendorLow, devHigh, devLow):
        self.ip = ip
        #self.u = udp_socket(ip, 0x8894)
        self.u = udp_socket(ip, 0xc002)
        self.vendorHigh, self.vendorLow, self.devHigh, self.devLow = vendorHigh, vendorLow, devHigh, devLow

    def read_implicit(self, api, slot, subslot, idx):
        block = PNBlockHeader(PNBlockHeader.IDOReadRequestHeader, 60, 0x01, 0x00)
        iod = PNIODHeader(bytes(block), 0, bytes(16), api, slot, subslot, 0, idx, 4096, bytes(16), bytes(8), payload=bytes())
        nrd = PNNRDData(1500, len(iod), 1500, 0, len(iod), payload=iod)
        rpc = PNRPCHeader(0x04, PNRPCHeader.REQUEST,
            0x20, # Flags1
            0x00, # Flags2
            bytes([0x00, 0x00, 0x00]), # DRep
            0x00, # Serial High
            PNRPCHeader.OBJECT_UUID_PREFIX + bytes([0x00, 0x01, self.devHigh, self.devLow, self.vendorHigh, self.vendorLow]), # ObjectUUID
            PNRPCHeader.IFACE_UUID_DEVICE,
            bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), # ActivityUUID
            0, # ServerBootTime
            1, # InterfaceVersion
            0, # SequenceNumber
            PNRPCHeader.IMPLICIT_READ, # OperationNumber
            0xFFFF, # InterfaceHint
            0xFFFF, # ActivityHint
            len(nrd), # LengthOfBody
            0, # FragmentNumber
            0, # AuthenticationProtocol
            0, # SerialLow
            payload=nrd
        )
        self.u.send(bytes(rpc))
        
        data = self.u.recv(4096)
        rpc = PNRPCHeader(data)
        nrd = PNNRDData(rpc.payload)
        iod = PNIODHeader(nrd.payload)
        block = PNBlockHeader(iod.block_header)
        
        return iod

    def connect(self, src_mac):
        block = PNBlockHeader(0x0101, PNARBlockRequest.fmt_size - 2, 0x01, 0x00)
        ar = PNARBlockRequest(bytes(block),
            0x0006, # AR Type
            bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), # AR UUID
            0x1234, # Session key
            src_mac,
            PNRPCHeader.OBJECT_UUID_PREFIX + bytes([0x00, 0x01, self.devHigh, self.devLow, self.vendorHigh, self.vendorLow]),
            1 << 8, # AR Properties
            600, # Timeout factor
            0x8892, # udp port?
            2,
            bytes("tp", encoding="utf-8"), payload=bytes()
        )
        nrd = PNNRDData(1500, len(ar), 1500, 0, len(ar), payload=ar)
        rpc = PNRPCHeader(0x04, PNRPCHeader.REQUEST,
            0x20, # Flags1
            0x00, # Flags2
            bytes([0x00, 0x00, 0x00]), # DRep
            0x00, # Serial High
            PNRPCHeader.OBJECT_UUID_PREFIX + bytes([0x00, 0x01, self.devHigh, self.devLow, self.vendorHigh, self.vendorLow]), # ObjectUUID
            PNRPCHeader.IFACE_UUID_DEVICE,
            bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), # ActivityUUID
            0, # ServerBootTime
            1, # InterfaceVersion
            0, # SequenceNumber
            PNRPCHeader.CONNECT, # OperationNumber
            0xFFFF, # InterfaceHint
            0xFFFF, # ActivityHint
            len(nrd), # LengthOfBody
            0, # FragmentNumber
            0, # AuthenticationProtocol
            0, # SerialLow
            payload=nrd
        )
        print(bytes(ar))
        print(bytes(nrd))
        print(bytes(rpc))
        self.u.send(bytes(rpc))
    
    def read_inm0filter(self):
        data = self.read_implicit(api=0, slot=0, subslot=0, idx=0xF840).payload
        block = PNBlockHeader(data)
        data = data[6:]
        
        ret = {}
        
        num_api, = unpack(">H", data[:2])
        data = data[2:]
        for i_api in range(0, num_api):
            api, num_modules = unpack(">IH", data[:6])
            data = data[6:]
            ret[api] = {}
            for i_module in range(0, num_modules):
                slot_number, module_ident_num, num_subslots = unpack(">HIH", data[:8])
                data = data[8:]
                ret[api][slot_number] = (module_ident_num, {})
                for i_subslot in range(0, num_subslots):
                    subslot_number, submodule_ident_number = unpack(">HI", data[:6])
                    data = data[6:]
                    ret[api][slot_number][1][subslot_number] = submodule_ident_number
        
        return ret

