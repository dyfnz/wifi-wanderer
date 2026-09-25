#!/usr/bin/env python3
"""Generate synthetic 802.11 beacon captures (pcap + pcapng, radiotap link type) for
exercising Wi-Fi Wanderer's monitor-mode parser without root or a real capture.

  python3 tests/make_sample_pcap.py tests/sample.pcap tests/sample.pcapng
"""
import struct, sys, random

def radiotap(freq, signal, noise=-92, flags=0x00):
    present = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5) | (1 << 6)
    body = struct.pack('<Q', 123456789) + bytes([flags, 0x0c]) + struct.pack('<HH', freq, 0x0140 if freq > 3000 else 0x00a0)
    body += struct.pack('<bb', signal, noise)
    hdr = struct.pack('<BBHI', 0, 0, 8 + len(body), present)
    return hdr + body

def ie(id_, data): return bytes([id_, len(data)]) + data
def ext_ie(ext, data): return ie(255, bytes([ext]) + data)
def vendor(oui, data): return ie(221, bytes.fromhex(oui) + data)

def rsn(akms, pairwise=(4,), wpa1=False):
    suite = (b'\x00\x50\xf2' if wpa1 else b'\x00\x0f\xac')
    b = struct.pack('<H', 1) + suite + bytes([4])
    b += struct.pack('<H', len(pairwise)) + b''.join(suite + bytes([p]) for p in pairwise)
    b += struct.pack('<H', len(akms)) + b''.join(suite + bytes([a]) for a in akms)
    b += struct.pack('<H', 0)
    return vendor('0050f2', b'\x01' + b) if wpa1 else ie(48, b)

def wps(manufacturer=None, model=None, model_number=None, device=None):
    tlv = struct.pack('>HHB', 0x104a, 1, 0x10)
    for t, v in ((0x1021, manufacturer), (0x1023, model), (0x1024, model_number), (0x1011, device)):
        if v: tlv += struct.pack('>HH', t, len(v)) + v.encode()
    return vendor('0050f2', b'\x04' + tlv)

def mgmt(subtype, bssid, ssid, channel, ies, privacy=True, interval=100):
    fc = bytes([subtype << 4, 0x00])
    hdr = fc + b'\x00\x00' + b'\xff' * 6 + bssid + bssid + b'\x10\x00'
    cap = 0x0001 | (0x0010 if privacy else 0)
    body = struct.pack('<QHH', 0, interval, cap)
    body += ie(0, ssid) + ie(1, bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]))
    if channel <= 14 or channel < 200: body += ie(3, bytes([channel])) if channel <= 177 else b''
    body += ie(7, b'US\x20' + bytes([1, 11, 20]))
    return hdr + body + ies

def freq_for(band, ch):
    return {2: 2407 + 5 * ch, 5: 5000 + 5 * ch, 6: 5950 + 5 * ch}[band]

random.seed(7)
frames = []  # (band, channel, signal, frame_bytes)

def add(band, ch, signal, subtype, bssid_hex, ssid, ies, privacy=True, count=1):
    for _ in range(count):
        s = signal + random.randint(-3, 3)
        frames.append((freq_for(band, ch), s, mgmt(subtype, bytes.fromhex(bssid_hex), ssid, ch, ies, privacy)))

ht40 = ie(45, bytes([0x02, 0x00]) + b'\x00' * 24)
vht80 = ie(191, b'\x00' * 12) + ie(192, bytes([1, 42, 0, 0, 0]))
he = ext_ie(35, b'\x00' * 20)
eht = ext_ie(108, b'\x00' * 10)

# 1. TP-Link router: OUI + WPS declared (2.4 GHz, WPA2/3 transition)
add(2, 6, -48, 8, '3c52a1aabb01', b'Archer-Home', rsn([2, 8]) + wps('TP-Link', 'Archer AX55', 'AX3000', 'Archer AX55') + ht40 + he, count=42)
# 2. Same router 5 GHz radio
add(5, 36, -52, 8, '3c52a1aabb02', b'Archer-Home-5G', rsn([2, 8]) + wps('TP-Link', 'Archer AX55', 'AX3000') + ht40 + vht80 + he, count=38)
# 3. Randomized-MAC AP with only a Broadcom vendor IE + an Ubiquiti vendor IE (vendor IE inference)
add(5, 149, -61, 8, '0a1b2c3d4e5f', b'CoffeeShop', rsn([2]) + vendor('001018', b'\x02\x00\x00') + vendor('00156d', b'\x01\x00') + ht40 + vht80, count=25)
# 4. Cisco enterprise AP with Aironet IE (AP name) and WPA2-Enterprise
aironet = ie(133, bytes(10) + b'LOBBY-AP-01'.ljust(16, b'\x00') + bytes(4))
add(5, 44, -70, 8, '00b0e1aa0001', b'CorpNet', rsn([1]) + aironet + ht40 + vht80 + he, count=18)
# 5. Aruba AP with vendor IE AP name and WPA3-Enterprise 192
add(5, 100, -74, 8, '000b86bb0002', b'Aruba-Secure', rsn([12], pairwise=(9,)) + vendor('000b86', b'\x01' + b'AP-3F-EAST') + ht40 + vht80, count=12)
# 6. Open network (no privacy), Netgear via SSID hint on an unknown OUI
add(2, 1, -80, 8, '021122334455', b'NETGEAR-Guest', ht40, privacy=False, count=9)
# 7. WEP legacy
add(2, 11, -86, 8, '00a0c5cc0003', b'OldPrinter', ie(45, bytes(26)), count=6)
# 8. OWE (Enhanced Open)
add(5, 157, -66, 8, 'f0a731dd0004', b'', rsn([18]) + ht40 + vht80, count=15)
# 9. Hidden SSID beacon + probe response revealing it (Apple OUI)
add(5, 40, -58, 8, '3c22fb000005', b'', rsn([2]) + ht40 + vht80 + he, count=20)
add(5, 40, -58, 5, '3c22fb000005', b'SecretApple', rsn([2]) + ht40 + vht80 + he, count=3)
# 10. 6 GHz Wi-Fi 6E/7 AP with HE Operation 6 GHz info (channel 37, 160 MHz), WPA3-only
he_op = ext_ie(36, bytes([0x00, 0x00, 0x02]) + bytes([0x01]) + bytes([0xfc, 0xff]) + bytes([37, 0x03, 47, 0, 0]))
add(6, 37, -55, 8, '9c3e53ee0006', b'Wanderer-6E', rsn([8], pairwise=(4,)) + he + he_op + eht, count=30)
# 11. WPA1-only legacy AP with mixed WPA/WPA2
add(2, 3, -77, 8, '0022f7aa0007', b'LegacyMix', rsn([2], wpa1=True) + rsn([2]) + ie(45, bytes(26)), count=8)
# 12. Unicode SSID
add(2, 9, -63, 8, '18b430aa0008', 'Café ☕ Wi‑Fi 日本'.encode(), rsn([2, 8]) + wps('Google', 'Nest Wifi Pro') + ht40 + he, count=22)

random.shuffle(frames)

def write_pcap(path):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127))
        t = 1700000000
        for i, (freq, sig, fr) in enumerate(frames):
            pkt = radiotap(freq, sig) + fr
            f.write(struct.pack('<IIII', t + i // 10, (i % 10) * 100000, len(pkt), len(pkt)) + pkt)

def block(btype, body):
    body += b'\x00' * (-len(body) % 4)
    total = 12 + len(body)
    return struct.pack('<II', btype, total) + body + struct.pack('<I', total)

def write_pcapng(path):
    with open(path, 'wb') as f:
        f.write(block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        f.write(block(1, struct.pack('<HHI', 127, 0, 65535)))
        for i, (freq, sig, fr) in enumerate(frames):
            pkt = radiotap(freq, sig) + fr
            ts = (1700000000 * 1000000) + i * 100000
            f.write(block(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(pkt), len(pkt)) + pkt))

out = sys.argv[1:] or ['tests/sample.pcap', 'tests/sample.pcapng']
for p in out:
    (write_pcapng if p.endswith('ng') else write_pcap)(p)
    print('wrote', p, 'frames:', len(frames))
