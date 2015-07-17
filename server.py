from struct import unpack
import argparse
import binascii

from flask import Flask, request, render_template, redirect, url_for


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
        con = rpc.RPCCon(info)
        con.connect(src)
        conns[name] = (info, con)
    return conns[name]


@app.route("/")
def index():
    dcp.send_discover(s, src)
    resp = [dcp.DCPDeviceDescription(mac, blocks) for mac, blocks in dcp.read_response(s, src).items()]
    return render_template("discover.html", resp=resp)

@app.route("/device")
def device():
    name = request.values.get('name')
    info, con = get_connection(name)
    data = con.read_inm0filter()
    return render_template("device.html", info=info, data=data)

@app.route("/inm0", methods=["GET", "POST"])
def inm0():
    name = request.values.get('name')
    
    api     = int(request.values.get('api'))
    slot    = int(request.values.get('slot'))
    subslot = int(request.values.get('subslot'))
    
    info, con = get_connection(name)
    payload = con.read(api, slot, subslot, idx=PNInM0.IDX).payload
    if len(payload) != 0:
        data = PNInM0(payload)
    else:
        data = None
    
    idx = request.values.get('idx')
    paramdata = None
    if idx is not None:
        _idx = int(idx, 16)
        if request.values.get('action') == "write":
            paramdata = request.values.get('data')
            con.write(api, slot, subslot, _idx, binascii.unhexlify(paramdata.replace(":", "")))
        else:
            paramdata = to_hex(con.read(api, slot, subslot, idx=_idx).payload)
    else:
        idx = ""
    
    return render_template("inm0.html", name=name, api=api, slot=slot, subslot=subslot, idx=idx, data=data, paramdata=paramdata, inm1_supported=(data.im_supported&1<<1 if data is not None else False))

@app.route("/inm1", methods=["GET", "POST"])
def inm1():
    name = request.values.get('name')
    
    api     = int(request.values.get('api'))
    slot    = int(request.values.get('slot'))
    subslot = int(request.values.get('subslot'))
    
    info, con = get_connection(name)
    
    data = PNInM1(con.read(api, slot, subslot, idx=PNInM1.IDX).payload)
    
    if request.method == 'POST':
        function = request.values.get('function')
        location = request.values.get('location')
        inm1 = PNInM1(data.block_header, bytes(function, "utf-8"), bytes(location, "utf-8"))
        con.write(api, slot, subslot, PNInM1.IDX, inm1)
        return redirect(url_for("inm1", name=name, api=api, slot=slot, subslot=subslot))
    else:
        return render_template("inm1.html", name=name, api=api, slot=slot, subslot=subslot, data=data)

@app.route("/rename")
def rename():
    mac = request.values.get('mac')
    name = request.values.get('name')
    
    old_name = dcp.get_param(s, src, mac, "name").decode()
    
    # delete connection
    if old_name in conns.keys():
        del conns[old_name]
    
    dcp.set_param(s, src, mac, "name", name)
    
    return redirect(url_for("device", name=name))

app.run(debug=True)
