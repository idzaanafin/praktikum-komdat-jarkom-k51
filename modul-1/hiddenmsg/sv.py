# # convert HID keyboard data

# key_map = {
#     4: 'a', 5: 'b', 6: 'c', 7: 'd', 8: 'e', 9: 'f', 10: 'g', 11: 'h', 12: 'i', 13: 'j',
#     14: 'k', 15: 'l', 16: 'm', 17: 'n', 18: 'o', 19: 'p', 20: 'q', 21: 'r', 22: 's', 
#     23: 't', 24: 'u', 25: 'v', 26: 'w', 27: 'x', 28: 'y', 29: 'z', 30: '1', 31: '2', 
#     32: '3', 33: '4', 34: '5', 35: '6', 36: '7', 37: '8', 38: '9', 39: '0', 40: '\n',
#     44: ' ', 45: '-', 46: '=', 47: '[', 48: ']', 49: '\\', 51: ';', 52: '\'', 54: ',', 
#     55: '.', 56: '/'
# }


# data = [
    
# ]

# for i in data:
#     print(key_map[i],end='')



import sys
from scapy.all import rdpcap
USAGE_ID_TO_KEY = {
    0x04: "a", 0x05: "b", 0x06: "c", 0x07: "d", 0x08: "e",
    0x09: "f", 0x0A: "g", 0x0B: "h", 0x0C: "i", 0x0D: "j",
    0x0E: "k", 0x0F: "l", 0x10: "m", 0x11: "n", 0x12: "o",
    0x13: "p", 0x14: "q", 0x15: "r", 0x16: "s", 0x17: "t",
    0x18: "u", 0x19: "v", 0x1A: "w", 0x1B: "x", 0x1C: "y",
    0x1D: "z",
    0x1E: "1", 0x1F: "2", 0x20: "3", 0x21: "4", 0x22: "5",
    0x23: "6", 0x24: "7", 0x25: "8", 0x26: "9", 0x27: "0",
    0x28: "\n", 0x2C: " ", 0x2D: "-", 0x2E: "=", 0x2F: "[",
    0x30: "]", 0x31: "\\", 0x33: ";", 0x34: "'", 0x36: ",",
    0x37: ".", 0x38: "/"
}

SHIFTED = {
    "1": "!", "2": "@", "3": "#", "4": "$", "5": "%",
    "6": "^", "7": "&", "8": "*", "9": "(", "0": ")",
    "-": "_", "=": "+", "[": "{", "]": "}", "\\": "|",
    ";": ":", "'": "\"", ",": "<", ".": ">", "/": "?"
}

def decode_hid_report(report: bytes) -> str:
    """Decode single 8-byte HID report to character(s)."""
    if len(report) < 3:
        return ""
    mod, _, *keys = report[:8]
    shift = mod & 0x22 or mod & 0x02 or mod & 0x20 or mod & 0x10 or mod & 0x01
    out = ""
    for k in keys:
        if k == 0:
            continue
        ch = USAGE_ID_TO_KEY.get(k, "")
        if shift and ch in SHIFTED:
            ch = SHIFTED[ch]
        elif shift and ch.isalpha():
            ch = ch.upper()
        out += ch
    return out

def main(pcap_path):
    packets = rdpcap(pcap_path)
    for i, pkt in enumerate(packets, 1):
        print(decode_hid_report(pkt.load[-8:]),end='')


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python read_pcap.py file.pcap[.ng]")
    else:
        main(sys.argv[1])
