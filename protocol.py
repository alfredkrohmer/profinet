from collections import namedtuple


from util import *


# ----------------------------------------------------------------------------------------------
#
#     DCP
#

EthernetHeader = make_packet("EthernetHeader", (
        ("dst",  ("6s", mac2s)),
        ("src",  ("6s", mac2s)),
        ("type", ("H", "0x%04X"))
))

EthernetVLANHeader = make_packet("EthernetHeader", (
        ("dst",  ("6s", mac2s)),
        ("src",  ("6s", mac2s)),
        ("tpid", ("H", "0x%04X")),
        ("tci",  ("H", "0x%04X")),
        ("type", ("H", "0x%04X"))
))

PNDCPHeader = make_packet("PNDCPHeader", (
    ("frame_id",     ("H", "0x%04X")),
    ("service_id",   "B"),
    ("service_type", "B"),
    ("xid",          ("I", "0x%08X")),
    ("resp",         "H"),
    ("length",       "H")
), statics={
    "ETHER_TYPE": 0x8892,
    "GET": 3,
    "SET": 4,
    "IDENTIFY": 5,
    "REQUEST": 0,
    "RESPONSE": 1
})

class IPConfiguration(namedtuple("IPConfiguration", ["address", "netmask", "gateway"])):
    def __str__(self):
        return ("IP configuration\n"
                "Address: %s\n"
                "Netmask: %s\n"
                "Gateway: %s\n") % (self.address, self.netmask, self.gateway)

class PNDCPBlockRequest(make_packet("PNDCPBlockRequest", (
    ("option",    "B"),
    ("suboption", "B"),
    ("length",    "H")
), payload_size_field="length")):
    def parse_ip(self):
        return IPConfiguration(s2ip(self.payload[0:4]), s2ip(self.payload[4:8]), s2ip(self.payload[8:12]))

class PNDCPBlock(make_packet("PNDCPBlockRequest", (
    ("option",    "B"),
    ("suboption", "B"),
    ("length",    "H"),
    ("status",    "H"),
), payload_size_field="length", payload_offset=-2)):

    IP_ADDRESS = (1, 2)
    NAME_OF_STATION = (2, 2)
    DEVICE_ID = (2, 3)
    ALL = (0xFF, 0xFF)
    
    def parse_ip(self):
        return IPConfiguration(s2ip(self.payload[0:4]), s2ip(self.payload[4:8]), s2ip(self.payload[8:12]))




# ----------------------------------------------------------------------------------------------
#
#     RPC
#

_UUID = [0x6c, 0x97, 0x11, 0xd1, 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D]

PNRPCHeader = make_packet("PNRPCHeader", (
    ("version",           "B"),
    ("packet_type",       "B"),
    ("flags1",            "B"),
    ("flags2",            "B"),
    ("drep",              "3s"),
    ("serial_high",       "B"),
    ("object_uuid",       "16s"),
    ("interface_uuid",    "16s"),
    ("activity_uuid",     "16s"),
    ("server_boot_time",  "I"),
    ("interface_version", "I"),
    ("sequence_number",   "I"),
    ("operation_number",  "H"),
    ("interface_hint",    "H"),
    ("activity_hint",     "H"),
    ("length_of_body",    "H"),
    ("fragment_number",   "H"),
    ("authentication_protocol", "B"),
    ("serial_low", "B")
), statics={
    "REQUEST": 0x00,
    "PING": 0x01,
    "RESPONSE": 0x02,
    "FAULT": 0x03,
    "WORKING": 0x04,
    "PONG": 0x05,
    "REJECT": 0x06,
    "ACK": 0x07,
    "CANCEL": 0x08,
    "FRAG_ACK": 0x09,
    "CANCEL_ACK": 0xA,

    "CONNECT": 0x00,
    "RELEASE": 0x01,
    "READ": 0x02,
    "WRITE": 0x03,
    "CONTROL": 0x04,
    "IMPLICIT_READ": 0x05,
    
    "IFACE_UUID_DEVICE": bytes([0xDE, 0xA0, 0x00, 0x01] + _UUID),
    "IFACE_UUID_CONTROLLER": bytes([0xDE, 0xA0, 0x00, 0x02] + _UUID),
    "IFACE_UUID_SUPERVISOR": bytes([0xDE, 0xA0, 0x00, 0x03] + _UUID),
    "IFACE_UUID_PARAMSERVER": bytes([0xDE, 0xA0, 0x00, 0x04] + _UUID),

    "OBJECT_UUID_PREFIX": bytes([0xDE, 0xA0, 0x00, 0x00, 0x6C, 0x97, 0x11, 0xD1, 0x82, 0x71])
})


PNNRDData = make_packet("PNNRDData", (
        ("args_maximum_status", "I"),
        ("args_length",         "I"),
        ("maximum_count",       "I"),
        ("offset",              "I"),
        ("actual_count",        "I")
))


PNIODHeader = make_packet("PNIODHeader", (
    ("block_header",    "6s"),
    ("sequence_number", "H"),
    ("ar_uuid",         "16s"),
    ("api",             "I"),
    ("slot",            "H"),
    ("subslot",         "H"),
    ("padding1",        "H"),
    ("index",           "H"),
    ("length",          "I"),
    ("target_ar_uuid",  "16s"),
    ("padding2",        "8s")
))


PNBlockHeader = make_packet("PNBlockHeader", (
    ("block_type",         "H"),
    ("block_length",       "H"),
    ("block_version_high", "B"),
    ("block_version_low",  "B")
), payload=False, statics={
    "IDOReadRequestHeader": 0x0009,
    "IODReadResponseHeader": 0x8009,
    "InM0": 0x0020,
    "InM0FilterDataSubModul": 0x0030,
    "InM0FilterDataModul": 0x0031,
    "InM0FilterDataDevice": 0x0032
})

PNARBlockRequest = make_packet("PNARBlockRequest", (
    ("block_header", "6s"),
    ("ar_type", "H"),
    ("ar_uuid", "16s"),
    ("session_key", "H"),
    ("cm_initiator_mac_address", "6s"),
    ("cm_initiator_object_uuid", "16s"),
    ("ar_properties", "I"),
    ("cm_initiator_activity_timeout_factor", "H"),
    ("initiator_udp_rtport", "H"),
    ("station_name_length", "H")
), vlf="cm_initiator_station_name", vlf_size_field="station_name_length")


PNIODReleaseBlock = make_packet("IODReleaseBlock", (
    ("block_header", "6s"),
    ("padding1",     "H"),
    ("ar_uuid",      "16s"),
    ("session_key",  "H"),
    ("padding2",     "H"),
    ("control_command", "H"),
    ("control_block_properties", "H")
))


PNInM0 = make_packet("InM0", (
    ("block_header",             "6s"),
    ("vendor_id_high",           "B"),
    ("vendor_id_low",            "B"),
    ("order_id",                 ("20s", decode_bytes)),
    ("im_serial_number",         ("16s", decode_bytes)),
    ("im_hardware_revision",     "H"),
    ("sw_revision_prefix",       "B"),
    ("im_sw_revision_functional_enhancement", "B"),
    ("im_sw_revision_bug_fix",   "B"),
    ("im_sw_revision_internal_change", "B"),
    ("im_revision_counter",      "H"),
    ("im_profile_id",            "H"),
    ("im_profile_specific_type", "H"),
    ("im_version",               "H"),
    ("im_supported",             "H")
), payload=False, statics={ "IDX": 0xAFF0 })

PNInM1 = make_packet("InM1", (
    ("block_header",             "6s"),
    ("im_tag_function",          ("32s", decode_bytes)),
    ("im_tag_location",          ("22s", decode_bytes)),
), payload=False, statics={ "IDX": 0xAFF1 })


