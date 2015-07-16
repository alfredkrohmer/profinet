import argparse


import dcp
import rpc

from util import *
from protocol import *


parser = argparse.ArgumentParser()
parser.add_argument("-i", required=True,
                    help="use INTERFACE", metavar="INTERFACE")
parser.add_argument("action", choices=("discover", "get-param", "set-param", "read", "read-inm0-filter", "read-inm0", "read-inm1", "write-inm1"))
parser.add_argument("target", nargs='?', help="MAC address of the device")
parser.add_argument("param",  nargs='?', help="parameter to read/write")
parser.add_argument("value",  nargs='?', help="value to write")
parser.add_argument("additional1",  nargs='?', help="additional parameters")
parser.add_argument("additional2",  nargs='?', help="additional parameters")

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
elif args.action.startswith("read") or args.action.startswith("write"):
    print("Getting station info ...")
    info = rpc.get_station_info(s, src, args.target)
    con = rpc.RPCCon(info)

    print("Connecting to device ...")
    con.connect(src)
    
    if args.action == "read":
        print(con.read(api=int(args.param), slot=int(args.value), subslot=int(args.additional1), idx=int(args.additional2, 16)).payload)
        
    if args.action[5:] == "inm0-filter":

        data = con.read_inm0filter()
        for api in data.keys():
            for slot_number, (module_ident_number, subslots) in data[api].items():
                print("Slot %d has module 0x%04X" % (slot_number, module_ident_number))
                for subslot_number, submodule_ident_number in subslots.items():
                    print("  Subslot %d has submodule 0x%04X" % (subslot_number, submodule_ident_number))

    elif args.action[5:] == "inm0":
        inm0 = PNInM0(con.read(api=int(args.param), slot=int(args.value), subslot=int(args.additional1), idx=PNInM0.IDX).payload)
        print(inm0)

    elif args.action[5:] == "inm1":
        inm1 = PNInM1(con.read(api=int(args.param), slot=int(args.value), subslot=int(args.additional1), idx=PNInM1.IDX).payload)
        print(inm1)

    elif args.action[6:] == "inm1":
        api = int(args.param)
        slot = int(args.value)
        subslot = int(args.additional1)
        inm1 = PNInM1(con.read(api, slot, subslot, PNInM1.IDX).payload)
        inm1 = PNInM1(inm1.block_header, bytes(args.additional2, "utf-8"), inm1.im_tag_location)
        con.write(api, slot, subslot, PNInM1.IDX, inm1)
                        

