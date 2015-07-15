import argparse


import dcp
import rpc

from util import *
from protocol import *


parser = argparse.ArgumentParser()
parser.add_argument("-i", required=True,
                    help="use INTERFACE", metavar="INTERFACE")
parser.add_argument("action", choices=("discover", "get-param", "set-param", "read-implicit"))
parser.add_argument("target", nargs='?', help="MAC address of the device")
parser.add_argument("param",  nargs='?', help="parameter to read/write")
parser.add_argument("value",  nargs='?', help="value to write")

args = parser.parse_args()


s = ethernet_socket(args.i, 3)
src = get_mac(args.i)

if args.action == "discover":
    dcp.send_discover(s, src)
    dcp.read_response(s, src, debug=True)
elif args.action == "get-param":
    dcp.get_param(s, src, args.target, args.param)
elif args.action == "set-param":
    dcp.set_param(s, src, args.target, args.param, args.value)
elif args.action == "read-implicit":
    print("Getting station info ...")
    info = rpc.get_station_info(s, src, args.target)
    con = rpc.RPCCon(*info)
    con.connect(src)
    
    print("Reading I&M0 filter data ...")
    data = con.read_inm0filter()
    for api in data.keys():
        for slot_number, (module_ident_number, subslots) in data[api].items():
            print("Slot %d has module 0x%04X" % (slot_number, module_ident_number))
            for subslot_number, submodule_ident_number in subslots.items():
                print("  Subslot %d has submodule 0x%04X" % (subslot_number, submodule_ident_number))
                print("    Reading I&M0 data ...")
                
                iod = con.read_implicit(api, slot_number, subslot_number, PNInM0.IDX)
                if iod.length > 0:
                    inm0 = PNInM0(iod.payload)
                    block = PNBlockHeader(inm0.block_header)
                    print(inm0)
                else:
                    print("    No I&M0 data!")
                    continue
                
                if inm0.im_supported & 1 << 1:
                    print("    Reading I&M1 data ...")
                    inm1 = PNInM1(con.read_implicit(api, slot_number, subslot_number, PNInM1.IDX).payload)
                    print(inm1)
                
