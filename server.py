from struct import unpack
import argparse
import binascii

from flask import Flask, request, render_template, redirect


from protocol import *
import dcp, rpc


app = Flask(__name__)
conns = {}

parser = argparse.ArgumentParser()
parser.add_argument("-i", required=True,
                    help="use INTERFACE", metavar="INTERFACE")
args = parser.parse_args()

s = ethernet_socket(args.i, 3)
src = get_mac(args.i)

def get_connection(name):
    if name not in conns.keys():
        info = rpc.get_station_info(s, src, name)
        conns[name] = rpc.RPCCon(info)
    return conns[name]


@app.route("/")
def index():
    dcp.send_discover(s, src)
    resp = [dcp.DCPDeviceDescription(mac, blocks) for mac, blocks in dcp.read_response(s, src).items()]
    return render_template("discover.html", resp=resp)

@app.route("/device")
def device():
    name = request.args.get('name')
    con = get_connection(name)
    data = con.read_inm0filter()
    return render_template("device.html", info=info, data=data)

@app.route("/inm0")
def inm0():
    name = request.args.get('name')
    
    api     = int(request.args.get('name'))
    slot    = int(request.args.get('name'))
    subslot = int(request.args.get('name'))
    
    con = get_connection(name)
    data = PNInM0(con.read(api, slot, subslot, idx=PNInM0.IDX).payload)
    
    idx = request.args.get('idx')
    paramdata = None
    if idx is not None:
        if request.args.get('action') == "write":
            paramdata = binascii.unhexlify(request.args.get('data').replace(":", ""))
            con.write(api, slot, subslot, idx, paramdata)
        else:
            paramdata = con.read(api, slot, subslot, idx=idx).payload
    
    return render_template("inm0.html", name=name, data=data, paramdata=paramdata)

@app.route("/inm1")
def inm1():
    name = request.args.get('name')
    
    api     = int(request.args.get('name'))
    slot    = int(request.args.get('name'))
    subslot = int(request.args.get('name'))
    
    con = get_connection(name)
    
    data = PNInM1(con.read(api, slot, subslot, idx=PNInM1.IDX).payload)
    
    if request.method == 'POST':
        function = request.args.get('function')
        location = request.args.get('location')
        inm1 = PNInM1(data.block_header, bytes(function, "utf-8"), bytes(location, "utf-8"))
        con.write(api, slot, subslot, PNInM1.IDX, inm1)
        return redirect(url_for("inm1", name=name, api=api, slot=slot, subslot=subslot))
    else:
        return render_template("inm0.html", name=name, data=data)

@app.route("/rename")
def rename():
    mac = request.args.get('mac')
    name = request.args.get('name')
    
    old_name = dcp.get_param(s, src, mac, "name")
    
    # move connection
    conns[name] = conns[old_name]
    del conns[old_name]
    
    dcp.set_param(s, src, mac, "name", name)
    
    return redirect(url_for("device", name=name))

app.run(debug=True)
