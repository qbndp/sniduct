"""TLS ClientHello 解析：从首包提取 SNI。"""
from __future__ import annotations


def extract_sni(data: bytes) -> str:
    if len(data) < 44 or data[0] != 0x16:
        return ""
    rec_len = int.from_bytes(data[3:5], "big")
    if rec_len + 5 > len(data):
        rec_len = len(data) - 5
    rec = data[5:5 + rec_len]
    if len(rec) < 38 or rec[0] != 0x01:
        return ""
    pos = 1 + 3 + 2 + 32
    if pos >= len(rec):
        return ""
    sid_len = rec[pos]
    pos += 1 + sid_len
    if pos + 2 > len(rec):
        return ""
    cs_len = int.from_bytes(rec[pos:pos + 2], "big")
    pos += 2 + cs_len
    if pos >= len(rec):
        return ""
    cm_len = rec[pos]
    pos += 1 + cm_len
    if pos + 2 > len(rec):
        return ""
    ext_len = int.from_bytes(rec[pos:pos + 2], "big")
    pos += 2
    end = min(pos + ext_len, len(rec))
    while pos + 4 <= end:
        ext_type = int.from_bytes(rec[pos:pos + 2], "big")
        e_len = int.from_bytes(rec[pos + 2:pos + 4], "big")
        pos += 4
        if ext_type == 0x0000 and pos + 5 <= end:
            pos += 2
            name_type = rec[pos]
            pos += 1
            name_len = int.from_bytes(rec[pos:pos + 2], "big")
            pos += 2
            if name_type == 0 and pos + name_len <= end:
                return rec[pos:pos + name_len].decode("ascii", errors="ignore")
        pos += e_len
    return ""
