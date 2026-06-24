"""JA3 TLS ClientHello fingerprinting — stdlib only."""
import hashlib
import struct

# GREASE values (RFC 8701)
GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a,
           0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada,
           0xeaea, 0xfafa}


def _u16(data, off):
    return struct.unpack_from(">H", data, off)[0]


def parse_client_hello(data: bytes) -> dict:
    """Parse a raw TLS record containing a ClientHello.
    Returns dict with keys: version, ciphers, extensions, curves, point_formats, ja3, ja3_string.
    Returns minimal dict on parse error.
    """
    try:
        if len(data) < 5 or data[0] != 0x16:
            return _empty()
        rec_len = _u16(data, 3)
        if len(data) < 5 + rec_len:
            return _empty()
        hs = data[5:]
        if hs[0] != 0x01:  # ClientHello
            return _empty()
        hs_len = (hs[1] << 16) | (hs[2] << 8) | hs[3]
        if len(hs) < 4 + hs_len:
            return _empty()
        ch = hs[4:4 + hs_len]
        off = 0
        version = _u16(ch, off); off += 2  # legacy version
        off += 32  # random
        sess_len = ch[off]; off += 1 + sess_len
        cs_len = _u16(ch, off); off += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            c = _u16(ch, off + i)
            if c not in GREASE and c != 0x00ff:
                ciphers.append(c)
        off += cs_len
        comp_len = ch[off]; off += 1 + comp_len

        exts, curves, point_fmts = [], [], []
        if off + 2 <= len(ch):
            ext_total = _u16(ch, off); off += 2
            end = off + ext_total
            while off + 4 <= end:
                etype = _u16(ch, off); off += 2
                elen = _u16(ch, off); off += 2
                edata = ch[off:off + elen]; off += elen
                if etype in GREASE:
                    continue
                exts.append(etype)
                if etype == 0x000a and len(edata) >= 4:  # supported_groups
                    gl = _u16(edata, 0)
                    for i in range(2, 2 + gl, 2):
                        g = _u16(edata, i)
                        if g not in GREASE:
                            curves.append(g)
                elif etype == 0x000b and len(edata) >= 2:  # point formats
                    pfl = edata[0]
                    point_fmts = list(edata[1:1 + pfl])

        def lst(items): return "-".join(str(x) for x in items) if items else ""
        ja3_str = f"{version},{lst(ciphers)},{lst(exts)},{lst(curves)},{lst(point_fmts)}"
        ja3 = hashlib.md5(ja3_str.encode()).hexdigest()
        return {"version": version, "ciphers": ciphers, "extensions": exts,
                "curves": curves, "point_formats": point_fmts,
                "ja3": ja3, "ja3_string": ja3_str}
    except Exception:
        return _empty()


def _empty():
    return {"version": 0, "ciphers": [], "extensions": [], "curves": [],
            "point_formats": [], "ja3": "00000000000000000000000000000000", "ja3_string": ""}
