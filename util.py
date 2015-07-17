from socket import *
from fcntl import ioctl
from sys import argv, exit, stdout, stderr
from struct import pack, unpack, calcsize
from collections import namedtuple, OrderedDict

import time


def to_hex(s):
    return ":".join("{:02x}".format(c) for c in s)

def s2mac(s):
    return bytes([int(num, 16) for num in s.split(':')])

def mac2s(m):
    return ':'.join(hex(num)[2:].zfill(2) for num in m)

def get_mac(ifname):
    s = socket(AF_INET, SOCK_DGRAM)
    info = ioctl(s.fileno(), 0x8927,  pack('256s', bytes(ifname[:15], "ascii")))
    return info[18:24]

def ethernet_socket(interface, ethertype):
    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((interface, ethertype))
    return s

def udp_socket(host, port):
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect((host, port))
    return s

def s2ip(i):
    return '.'.join(str(o) for o in i)

def decode_bytes(s):
    return s.decode()

class max_timeout(object):
    def __init__(self, seconds):
        self.seconds = seconds
    def __enter__(self):
        self.die_after = time.time() + self.seconds
        return self
    def __exit__(self, type, value, traceback):
        pass
    @property
    def timed_out(self):
        return time.time() > self.die_after

"""
class timeout:
    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message
    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)
    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)
    def __exit__(self, type, value, traceback):
        signal.alarm(0)
"""

# vlf = variable length field
def make_packet(name, fields, statics={}, payload=True, payload_size_field=None, payload_offset=0, vlf=None, vlf_size_field=None):
    fields = OrderedDict(fields)
    fmt = ">" + "".join([(f[0] if isinstance(f, tuple) else f) for f in fields.values()])
    size = calcsize(fmt)
    
    f = list(fields.keys())
    if vlf is not None:
        f.append(vlf)
    if payload:
        f.append("payload")
    
    t = namedtuple(name, f)
    class _class(t):
    
        def __new__(cls, *args, **kwargs):
        
            # unpack (parse packet)
            if len(args) == 1:
                data = args[0]
                
                # unpack known-size fields
                unpacked = unpack(fmt, data[0:size])
                
                kw = {}
                
                # handle variable length fields
                if vlf is not None:
                    vlf_size = unpacked[list(fields.keys()).index(vlf_size_field)]
                    kw[vlf] = data[size:size+vlf_size]
                else:
                    vlf_size = 0
                
                # handle payload
                if payload:
                    if payload_size_field is not None:
                        pl_size = unpacked[list(fields.keys()).index(payload_size_field)] + payload_offset
                        kw["payload"] = data[size+vlf_size:size+vlf_size+pl_size]
                    else:
                        kw["payload"] = data[size+vlf_size:]
                
                # finally create instance
                self = t.__new__(cls, *unpacked, **kw)

            # pack (create packet)
            else:
                self = t.__new__(cls, *args, **kwargs)

            return self

        def __str__(self):
            ret = "%s packet (%d bytes)\n" % (name, len(self))
            for k, v in fields.items():
                ret += k + ": "
                value = getattr(self, k)
                if isinstance(v, tuple):
                    if isinstance(v[1], str):
                        ret += v[1] % value
                    else:
                        ret += v[1](value)
                else:
                    ret += str(value)
                ret += "\n"
            return ret
        
        def __bytes__(self):
            packed = pack(fmt, *(getattr(self, key) for key in fields.keys()))
            if vlf is not None:
                packed += bytes(getattr(self, vlf))
            if payload:
                packed += bytes(self.payload)
            return packed

        def __len__(self):
            s = size
            if vlf is not None:
                s += len(bytes(getattr(self, vlf)))
            if payload:
                s += len(self.payload)
            return s

    _class.fmt = fmt
    _class.fmt_size = size

    for k, v in statics.items():
        setattr(_class, k, v)

    return _class

