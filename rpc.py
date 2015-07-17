from struct import unpack
from socket import MSG_WAITALL
from datetime import datetime

from util import *
from protocol import *

import dcp


def get_station_info(s, src, name):
    dcp.send_request(s, src, PNDCPBlock.NAME_OF_STATION, bytes(name, 'utf-8'))
    resp = list(dcp.read_response(s, src, once=True).items())[0]
    return dcp.DCPDeviceDescription(*resp)


class RPCCon:
    def __init__(self, info):
        self.info = info
        self.peer = (info.ip, 0x8894)
        
        self.ar_uuid = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        self.activity_uuid = self.ar_uuid
        
        self.local_object_uuid  = PNRPCHeader.OBJECT_UUID_PREFIX + bytes([0x00, 0x01, 0x76,              0x54,             0x32,                 0x10])
        self.remote_object_uuid = PNRPCHeader.OBJECT_UUID_PREFIX + bytes([0x00, 0x01, self.info.devHigh, self.info.devLow, self.info.vendorHigh, self.info.vendorLow])
        
        self.live = None
        
        self.u = socket(AF_INET, SOCK_DGRAM)


    def _create_rpc(self, operation, nrd):
        return PNRPCHeader(0x04, PNRPCHeader.REQUEST,
            0x20, # Flags1
            0x00, # Flags2
            bytes([0x00, 0x00, 0x00]), # DRep
            0x00, # Serial High
            self.remote_object_uuid,
            PNRPCHeader.IFACE_UUID_DEVICE,
            self.activity_uuid,
            0, # ServerBootTime
            1, # InterfaceVersion
            0, # SequenceNumber
            operation,
            0xFFFF, # InterfaceHint
            0xFFFF, # ActivityHint
            len(nrd),
            0, # FragmentNumber
            0, # AuthenticationProtocol
            0, # SerialLow
            payload=nrd
        )
    
    def _create_nrd(self, payload):
        return PNNRDData(1500, len(payload), 1500, 0, len(payload), payload=payload)

    def _check_timeout(self):
        if self.live is not None and (datetime.now() - self.live).seconds >= 10:
            self.connect()

    def connect(self, src_mac=None):
        if self.live is None:
            self.src_mac = src_mac

        block = PNBlockHeader(0x0101, PNARBlockRequest.fmt_size - 2, 0x01, 0x00)
        ar = PNARBlockRequest(bytes(block),
            0x0006, # AR Type
            self.ar_uuid, # AR UUID
            0x1234, # Session key
            self.src_mac,
            self.local_object_uuid,
            0x131, # AR Properties
            100, # Timeout factor
            0x8892, # udp port?
            2,
            bytes("tp", encoding="utf-8"), payload=bytes()
        )
        nrd = self._create_nrd(ar)
        rpc = self._create_rpc(PNRPCHeader.CONNECT, nrd)
        self.u.sendto(bytes(rpc), self.peer)
        
        data = self.u.recvfrom(4096)[0]
        # ignore response
        #rpc = PNRPCHeader(data)
        #nrd = PNNRDData(rpc.payload)
        #ar = PNARBlockRequest(nrd.payload)
        #block = PNBlockHeader(iod.block_header)
        
        self.live = datetime.now()

    def read(self, api, slot, subslot, idx):
        self._check_timeout()
        
        block = PNBlockHeader(PNBlockHeader.IDOReadRequestHeader, 60, 0x01, 0x00)
        iod = PNIODHeader(bytes(block), 0, self.ar_uuid, api, slot, subslot, 0, idx, 4096, bytes(16), bytes(8), payload=bytes())
        nrd = self._create_nrd(iod)
        rpc = self._create_rpc(PNRPCHeader.READ, nrd)
        self.u.sendto(bytes(rpc), self.peer)
        
        data = self.u.recvfrom(4096)[0]
        rpc = PNRPCHeader(data)
        nrd = PNNRDData(rpc.payload)
        iod = PNIODHeader(nrd.payload)
        block = PNBlockHeader(iod.block_header)
        
        self.live = datetime.now()
        
        return iod

    def read_implicit(self, api, slot, subslot, idx):
        block = PNBlockHeader(PNBlockHeader.IDOReadRequestHeader, 60, 0x01, 0x00)
        iod = PNIODHeader(bytes(block), 0, bytes(16), api, slot, subslot, 0, idx, 4096, bytes(16), bytes(8), payload=bytes())
        nrd = self._create_nrd(iod)
        rpc = self._create_rpc(PNRPCHeader.IMPLICIT_READ, nrd)
        self.u.sendto(bytes(rpc), self.peer)
        
        data = self.u.recvfrom(4096)[0]
        rpc = PNRPCHeader(data)
        nrd = PNNRDData(rpc.payload)
        iod = PNIODHeader(nrd.payload)
        block = PNBlockHeader(iod.block_header)
        
        return iod

    def write(self, api, slot, subslot, idx, data):
        self._check_timeout()
        block = PNBlockHeader(0x8, 60, 0x01, 0x00)
        iod = PNIODHeader(bytes(block), 0, self.ar_uuid, api, slot, subslot, 0, idx, len(data), bytes(16), bytes(8), payload=bytes(data))
        nrd = self._create_nrd(iod)
        rpc = self._create_rpc(PNRPCHeader.WRITE, nrd)
        self.u.sendto(bytes(rpc), self.peer)
        
        data = self.u.recvfrom(4096)[0]
        # ignore response
        
        self.live = datetime.now()


    def read_inm0filter(self):
        data = self.read(api=0, slot=0, subslot=0, idx=0xF840).payload
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

