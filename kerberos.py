from binascii import unhexlify
from pyasn1.codec.der.decoder import decode as der_decode
from impacket.krb5.asn1 import (AS_REQ, AS_REP, AP_REQ, TGS_REP,Authenticator,EncryptedData, PA_ENC_TS_ENC,EncASRepPart, EncTGSRepPart, EncTicketPart)
from impacket.krb5.crypto import _enctype_table, Key
from datetime import datetime, timezone
import argparse
import sys
from impacket.krb5.pac import PAC_LOGON_INFO
from impacket.krb5 import pac as _pac
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.krb5.constants import ChecksumTypes
from struct import unpack_from
import datetime as _dt
import builtins as _bi
from impacket.krb5.asn1 import EncTicketPart, AuthorizationData
try:
    from impacket.krb5.pac import KERB_VALIDATION_INFO as _VALIDATION_CLS
except Exception:
    try:
        from impacket.krb5.pac import VALIDATION_INFO as _VALIDATION_CLS
    except Exception:
        _VALIDATION_CLS = None

##################################################

PAC_VERBOSE = False

##################################################

int = _bi.int
str = _bi.str
len = _bi.len
bytes = _bi.bytes

##################################################

PAC_ATTRS = {  
    0x00000001: "PAC_WAS_REQUESTED",
    0x00000002: "PAC_WAS_GIVEN_IMPLICITLY",
}

##################################################
def flags_to_names_map(val: int, mapping: dict) -> str:
    try:
        names = [name for bit, name in mapping.items() if val & bit]
        return ", ".join(names) if names else "0"
    except Exception:
        return str(val)

##################################################
def _nt_to_dt_str(nt: int) -> str:
    try:
        if nt in (0, None):
            return "Never"
       
        if nt == 0x7FFFFFFFFFFFFFFF or nt == 0x7fffffff_ffffffff:
            return "Infinity"
        unix_seconds = (nt / 10_000_000) - 11644473600
        return _dt.datetime.utcfromtimestamp(unix_seconds).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(nt)

################################################## 

class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    DIM     = "\033[2m"
##################################################

FLAG_MASKS = [
    (0x40000000, "forwardable"),
    (0x20000000, "forwarded"),
    (0x10000000, "proxiable"),
    (0x08000000, "proxy"),
    (0x04000000, "may_postdate"),
    (0x02000000, "postdated"),
    (0x01000000, "invalid"),
    (0x00800000, "renewable"),
    (0x00400000, "initial"),
    (0x00200000, "pre_authent"),
    (0x00100000, "hw_authent"),
    (0x00040000, "ok_as_delegate"), 
    (0x00010000, "name_canonicalize"),
]

##################################################
GROUP_ATTRS = {
    0x00000001: "MANDATORY",
    0x00000002: "ENABLED_BY_DEFAULT",
    0x00000004: "ENABLED",
    0x00000008: "OWNER",
    0x00000010: "USE_FOR_DENY_ONLY",
    0x00000020: "INTEGRITY",
    0x00000040: "INTEGRITY_ENABLED",
    0x00000080: "RESOURCE",
    0x20000000: "LOGON_ID",
    0x40000000: "SID_LOGON",
    0x80000000: "SID_AND_ATTRIBUTES_SE_GROUP_MANDATORY", 
}

##################################################

RID_NAME_MAP = {
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    544: "Administrators",
    545: "Users",
    546: "Guests",
    551: "Backup Operators",
}
##################################################
UAC_FLAGS = {
    0x0001: "SCRIPT",
    0x0002: "ACCOUNTDISABLE",
    0x0010: "HOMEDIR_REQUIRED",
    0x0020: "LOCKOUT",
    0x0080: "PASSWD_NOTREQD",
    0x0100: "PASSWD_CANT_CHANGE",
    0x0200: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0400: "TEMP_DUPLICATE_ACCOUNT",
    0x0800: "NORMAL_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQ_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x04000000: "PARTIAL_SECRETS_ACCOUNT",
}

##################################################

SE_GROUP_ATTRS = {
    0x00000001: "SE_GROUP_MANDATORY",
    0x00000002: "SE_GROUP_ENABLED_BY_DEFAULT",
    0x00000004: "SE_GROUP_ENABLED",
    0x00000008: "SE_GROUP_OWNER",
    0x00000010: "SE_GROUP_USE_FOR_DENY_ONLY",
    0x20000000: "SE_GROUP_RESOURCE",
    0x40000000: "SE_GROUP_LOGON_ID_LOW",
    0x80000000: "SE_GROUP_LOGON_ID_HIGH",
}

##################################################
CHECKSUM_NAMES = {
    0x00000000: "NONE",
    0x00000001: "CRC32",
    0x00000007: "RSA_MD5",
    0x0000000F: "HMAC_SHA1_96_AES128",
    0x00000010: "HMAC_MD5",
    0x00000011: "HMAC_SHA1_96_AES256",
}
##################################################

_CHECKSUM_INFO = {
    0x10: ("HMAC_MD5 (RC4-HMAC)", 16),
    0x11: ("HMAC_SHA1_96_AES128", 12),
    0x12: ("HMAC_SHA1_96_AES256", 12),
}

##################################################

PAC_ATTR= {
    0x00000001: "PAC_WAS_REQUESTED",
    0x00000002: "PAC_WAS_GIVEN_IMPLICITLY",
}

##################################################

USER_FLAGS = {
    0x00000020: "LOGON_EXTRA_SIDS",
}
##################################################

PAC_ATTR_FLAGS = {
    0x00000001: "PAC_WAS_REQUESTED",
    0x00000002: "PAC_WAS_GIVEN_IMPLICITLY",
}
##################################################

def parse_pac_claims_info(buf: bytes):
    out = {}
    try:
        if len(buf) < 16:
            return {"_error": f"ClaimsInfo too short ({len(buf)} bytes)"}

        version = unpack_from("<I", buf, 0)[0]
        length  = unpack_from("<I", buf, 4)[0]

        out["Version"] = version
        out["ClaimsLength"] = length

        if length > 0 and len(buf) >= 8 + length:
            claims_blob = buf[8:8+length]
            out["ClaimsHex"] = claims_blob.hex()
        else:
            out["ClaimsHex"] = "<empty>"
    except Exception as e:
        out["_error"] = f"parse_pac_claims_info failed: {e}"
    return out

##################################################

def parse_pac_signature(buf: bytes):
    out = {}
    if len(buf) < 4:
        return out

    sig_type = unpack_from("<I", buf, 0)[0]
    algo_name, want_len = _CHECKSUM_INFO.get(sig_type, (None, None))

    sig_raw = buf[4:]
    if want_len is not None and len(sig_raw) >= want_len:
        sig = sig_raw[:want_len]
    else:
        sig = sig_raw.rstrip(b"\x00")

    out["SignatureType"] = f"{sig_type} (0x{sig_type:08x})"
    if algo_name:
        out["SignatureAlgo"] = algo_name
    out["SignatureLen"] = len(sig)
    out["Signature"] = sig.hex()
    return out
##################################################

def pac_coverage_report(pac_bytes: bytes, pac):
    total = len(pac_bytes)

    cbuf = pac.get('cBuffers', 0)
    hdr_dir_len = 8 + 16 * cbuf 
    spans = []
    for e in pac['entries']:
        start = e['offset']; end = e['offset'] + e['size']
        ok = 0 <= start <= end <= total
        spans.append((start, end, ok, e['type']))

    spans.append((0, min(hdr_dir_len, total), True, -1)) 

    spans.sort()
    covered = 0
    last_end = 0
    notes = []
    for start, end, ok, t in spans:
        if not ok:
            notes.append(f"type={t} out-of-bounds [{start}:{end}] total={total}")
            continue

        if start > last_end:
            gap_size = start - last_end
            if start % 8 == 0 and gap_size <= 7:
                notes.append(f"expected 8-byte padding [{last_end}:{start}]")
            else:
                notes.append(f"gap [{last_end}:{start}]")

        covered += max(0, end - max(last_end, start))
        last_end = max(last_end, end)

    if last_end < total:
        tail_gap = total - last_end
        if tail_gap <= 7:
            notes.append(f"expected tail padding [{last_end}:{total}]")
            covered += tail_gap
        else:
            notes.append(f"gap [{last_end}:{total}]")

    pct = (covered / total * 100.0) if total else 0.0
    print(f"{Colors.DIM}PAC coverage:{Colors.RESET} {covered}/{total} bytes ({pct:.1f}%)")
    if notes:
        print(f"{Colors.DIM}PAC notes:{Colors.RESET} " + " | ".join(notes))

##################################################

def group_attr_names(attrs: int) -> str:
    names = [name for bit, name in GROUP_ATTRS.items() if attrs & bit]
    return ", ".join(names) if names else f"0x{attrs:08x}"

##################################################

def flags_to_names_masked(v: int):
    names = [name for mask, name in FLAG_MASKS if v & mask]
    return names or [f"0x{v:08x}"]

##################################################

def flags_to_names(v: int):
    KERB_FLAGS = [(1,"forwardable"),(8,"renewable"),(9,"initial"),(10,"pre_authent"),(15,"enc_pa_rep")]
    names = [name for bit, name in KERB_FLAGS if v & (1 << bit)]
    return names or [f"0x{v:08x}"]

##################################################

def sid_to_str(sid_obj) -> str | None:
    try:
        return sid_obj.formatCanonical() if hasattr(sid_obj, "formatCanonical") else str(sid_obj)
    except Exception:
        try:
            return str(sid_obj)
        except Exception:
            return None
            
##################################################

def join_domain_sid_and_rid(domain_sid_str: str | None, rid: int | None) -> str | None:
    if not domain_sid_str or rid is None:
        return None
    if domain_sid_str.startswith("S-"):
        return f"{domain_sid_str}-{rid}"
    return None
##################################################

def read_utf16le(buf, off, ln):
    try:
        if ln and 0 <= off < len(buf) and off+ln <= len(buf):
            return buf[off:off+ln].decode('utf-16le', errors='ignore')
    except Exception:
        pass
    return None
##################################################

def filetime_to_dt_str(lo, hi):
    ft = (int(hi) << 32) | int(lo)
    if ft == 0: return "-"
    unix_100ns = ft - 116444736000000000
    ts = unix_100ns / 10_000_000
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

##################################################

def extract_pac_bytes_from_ad(ad_blob: bytes) -> bytes:
    if not (len(ad_blob) > 0 and ad_blob[0] == 0x30):
        return ad_blob
    authz, _ = der_decode(ad_blob, asn1Spec=AuthorizationData())
    for entry in authz:
        ad_type = int(entry['ad-type'])
        ad_data = bytes(entry['ad-data'])
        if ad_type == 128:
            return ad_data
        if ad_type == 1:
            try:
                inner, _ = der_decode(ad_data, asn1Spec=AuthorizationData())
                for sub in inner:
                    if int(sub['ad-type']) == 128:
                        return bytes(sub['ad-data'])
            except Exception:
                pass
    raise ValueError("AD-WIN2K-PAC not found in AuthorizationData")
##################################################

def parse_pac_raw(pac: bytes):
    if len(pac) < 8:
        raise ValueError("PAC too short")
    cBuffers, version = unpack_from("<II", pac, 0)
    entries = []
    off = 8
    for i in range(cBuffers):
        if off + 16 > len(pac):
            raise ValueError("PAC entries truncated")
        ulType, cbSize, offset = unpack_from("<IIQ", pac, off)
        off += 16
        entries.append({"index": i, "type": ulType, "size": cbSize, "offset": offset,"data": pac[offset: offset + cbSize]})
    return {"cBuffers": cBuffers, "version": version, "entries": entries}

##################################################

def _read_us_selfrel(buf: bytes, us) -> str:
    try:
        ln  = _bi.int(us['Length'])
        off = _bi.int(us['Buffer'])
        if ln and 0 <= off <= len(buf) - ln:
            return buf[off:off+ln].decode('utf-16le', errors='ignore')
    except Exception:
        pass
    try:
        return us.string
    except Exception:
        return ""

##################################################

def _filetime_to_str_ft(ft_obj) -> str:
    try:
        lo = int(ft_obj['dwLowDateTime']); hi = int(ft_obj['dwHighDateTime'])
        if lo == 0xFFFFFFFF and hi == 0x7FFFFFFF:
            return "Infinity (absolute time)"
        val = (hi << 32) | lo
        if val == 0:
            return "-"
        import datetime
        return (datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=val/10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return "-"
##################################################

def parse_pac_client_info(buf: bytes):
    out = {}
    if len(buf) >= 10:
        lo, hi = unpack_from("<II", buf, 0)
        nlen = unpack_from("<H", buf, 8)[0]
        out["ClientName"] = read_utf16le(buf, 10, nlen) or ""
        out["ClientId"]   = filetime_to_dt_str(lo, hi)
    return out

##################################################

def parse_pac_upn_dns_info(buf: bytes):
    out = {}
    if len(buf) >= 12:
        upn_len, upn_off, dns_len, dns_off, flags = unpack_from("<HHHHI", buf, 0)
        upn = read_utf16le(buf, upn_off, upn_len)
        dns = read_utf16le(buf, dns_off, dns_len)
        
        if upn: 
            out["UPN"] = upn
        if dns: 
            out["DNSDomainName"] = dns
            
        flag_meanings = {
            0x00000001: "UPN_CONSTRUCTED",
            0x00000002: "S_SidSamSupplied"
        }
        flag_names = [name for bit, name in flag_meanings.items() if flags & bit]
        out["UPN_Flags"] = f"0x{flags:08x} ({', '.join(flag_names) if flag_names else 'Unknown'})"
        
    return out

##################################################

def parse_sid(buf: bytes, offset: int = 0):
    try:
        if len(buf) < offset+8: return None
        rev = buf[offset]; cnt = buf[offset+1]; ida = int.from_bytes(buf[offset+2:offset+8],"big")
        subs=[]; pos=offset+8
        for _ in range(cnt):
            subs.append(unpack_from("<I", buf, pos)[0]); pos+=4
        return "S-" + "-".join([str(rev), str(ida)] + [str(x) for x in subs])
    except Exception:
        return None

##################################################

def parse_pac_requestor(buf: bytes):
    sid = parse_sid(buf, 0); return {"UserSid": sid} if sid else {}

##################################################


def _fmt_gt(asn1_time) -> str:
    s = str(asn1_time)
    try:
        return _dt.datetime.strptime(s, "%Y%m%d%H%M%SZ").strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return s

##################################################

def _explain_attr_english(name: str) -> str | None:
    n = name.strip().upper()
    if n == "PAC_WAS_REQUESTED":
        return "— KDC returned a PAC because the client requested it."
    if n == "PAC_WAS_GIVEN_IMPLICITLY":
        return "— KDC included a PAC even if the client didn't explicitly request it."
    return None

##################################################

def parse_pac_attributes_info(buf: bytes):
    out = {}
    if len(buf) >= 4:
        flags = unpack_from("<I", buf, 0)[0]
        names = [name for bit, name in PAC_ATTR_FLAGS.items() if flags & bit]
        out["Flags"] = ", ".join(names) if names else ""
    return out

##################################################

def _filetime_to_iso(ft) -> str:
    try:
        lo = int(ft['dwLowDateTime']); hi = int(ft['dwHighDateTime'])
        if lo == 0xFFFFFFFF and hi == 0x7FFFFFFF:
            return "Infinity (absolute time)"
        val = (hi << 32) | lo
        if val == 0:
            return "-"
        base = _dt.datetime(1601, 1, 1)
        return (base + _dt.timedelta(microseconds=val/10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return "-"

##################################################

def parse_pac_logon_info(buf_bytes: bytes):
    info = {"User": {}, "Domain": {}, "Groups": [], "ExtraSids": [], "ResourceGroups": [], "Times": {}}
    
    try:
        ts1 = TypeSerialization1(buf_bytes)
        newdata = buf_bytes[len(ts1)+4:]
        try:
            from impacket.krb5.pac import KERB_VALIDATION_INFO
            kvi = KERB_VALIDATION_INFO()
        except ImportError:
            try:
                from impacket.krb5.pac import VALIDATION_INFO as KERB_VALIDATION_INFO
                kvi = KERB_VALIDATION_INFO()
            except ImportError:
                print(f"    {Colors.RED}Could not import KERB_VALIDATION_INFO{Colors.RESET}")
                return {"_error": "Could not import KERB_VALIDATION_INFO"}
        
        kvi.fromString(newdata)
        kvi.fromStringReferents(newdata[len(kvi.getData()):])


        try:
            info["User"]["RID"] = int(kvi["UserId"])
            print(f"    {Colors.GREEN}User RID: {info['User']['RID']}{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading UserId: {e}{Colors.RESET}")

        try:
            info["Domain"]["PrimaryGroupId"] = int(kvi["PrimaryGroupId"])
            print(f"    {Colors.GREEN}Primary Group RID: {info['Domain']['PrimaryGroupId']}{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading PrimaryGroupId: {e}{Colors.RESET}")

        try:
            info["Domain"]["GroupCount"] = int(kvi["GroupCount"])
            print(f"    {Colors.GREEN}Group Count: {info['Domain']['GroupCount']}{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading GroupCount: {e}{Colors.RESET}")

  
        try:
            if kvi["EffectiveName"]:
                info["User"]["UserName"] = str(kvi["EffectiveName"])
                print(f"    {Colors.GREEN}Effective Name: {info['User']['UserName']}{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading EffectiveName: {e}{Colors.RESET}")
            try:
                if kvi["UserName"]:
                    info["User"]["UserName"] = str(kvi["UserName"])
                    print(f"    {Colors.GREEN}User Name: {info['User']['UserName']}{Colors.RESET}")
            except Exception as e2:
                print(f"    {Colors.RED}Error reading UserName: {e2}{Colors.RESET}")

        try:
            if kvi["FullName"]:
                info["User"]["FullName"] = str(kvi["FullName"])
                print(f"    {Colors.GREEN}Full Name: {info['User']['FullName']}{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading FullName: {e}{Colors.RESET}")

        try:
            if kvi["LogonDomainName"]:
                info["Domain"]["LogonDomainName"] = str(kvi["LogonDomainName"])
                print(f"    {Colors.GREEN}Logon Domain: {info['Domain']['LogonDomainName']}{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading LogonDomainName: {e}{Colors.RESET}")

        try:
            if kvi["LogonServer"]:
                info["LogonServer"] = str(kvi["LogonServer"])
                print(f"    {Colors.GREEN}Logon Server: {info['LogonServer']}{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading LogonServer: {e}{Colors.RESET}")

        try:
            info["User"]["LogonCount"] = int(kvi["LogonCount"])
            print(f"    {Colors.GREEN}Logon Count: {info['User']['LogonCount']}{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading LogonCount: {e}{Colors.RESET}")

        try:
            info["User"]["BadPasswordCount"] = int(kvi["BadPasswordCount"])
            print(f"    {Colors.GREEN}Bad Password Count: {info['User']['BadPasswordCount']}{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading BadPasswordCount: {e}{Colors.RESET}")

        try:
            info["User"]["UserAccountControl"] = int(kvi["UserAccountControl"])
            uac = info["User"]["UserAccountControl"]
            uac_names = flags_to_names_map(uac, UAC_FLAGS)
            print(f"    {Colors.GREEN}User Account Control: {uac} ({uac_names}){Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading UserAccountControl: {e}{Colors.RESET}")

        try:
            info["User"]["UserFlags"] = int(kvi["UserFlags"])
            uf = info["User"]["UserFlags"]
            uf_names = flags_to_names_map(uf, USER_FLAGS)
            print(f"    {Colors.GREEN}User Flags: {uf} ({uf_names}){Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading UserFlags: {e}{Colors.RESET}")

        try:
            if kvi["LogonDomainId"]:
                info["Domain"]["LogonDomainId"] = kvi["LogonDomainId"].formatCanonical()
                print(f"    {Colors.GREEN}Logon Domain SID: {info['Domain']['LogonDomainId']}{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading LogonDomainId: {e}{Colors.RESET}")

        try:
            if hasattr(kvi, "UserSid") and kvi.UserSid:
                info["User"]["UserSid"] = kvi.UserSid.formatCanonical()
                print(f"    {Colors.GREEN}User SID: {info['User']['UserSid']}{Colors.RESET}")
            else:
                domain_sid = info["Domain"].get("LogonDomainId")
                user_rid = info["User"].get("RID")
                if domain_sid and user_rid:
                    user_sid = f"{domain_sid}-{user_rid}"
                    info["User"]["UserSid"] = user_sid
                    print(f"    {Colors.GREEN}User SID (calculated): {user_sid}{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading UserSid: {e}{Colors.RESET}")

        time_fields = [
            ("LogonTime", "Logon Time"),
            ("LogoffTime", "Logoff Time"), 
            ("KickOffTime", "Kickoff Time"),
            ("PasswordLastSet", "Password Last Set"),
            ("PasswordCanChange", "Password Can Change"),
            ("PasswordMustChange", "Password Must Change"),
            ("LastSuccessfulILogon", "Last Successful Logon"),
            ("LastFailedILogon", "Last Failed Logon")
        ]

        print(f"    {Colors.GREEN}Times:{Colors.RESET}")
        for field_name, display_name in time_fields:
            try:
                if hasattr(kvi, field_name):
                    ft = getattr(kvi, field_name)
                    if ft and hasattr(ft, 'dwLowDateTime') and hasattr(ft, 'dwHighDateTime'):
                        lo = int(ft.dwLowDateTime)
                        hi = int(ft.dwHighDateTime)
                        nt_time = (hi << 32) | lo
                        if nt_time != 0:
                            info["Times"][field_name] = nt_time
                            time_str = _nt_to_dt_str(nt_time)
                            print(f"      {display_name}: {Colors.CYAN}{time_str}{Colors.RESET}")
            except Exception as e:
                if "0" not in str(e) and "None" not in str(e):
                    print(f"      {Colors.DIM}Could not read {field_name}{Colors.RESET}")

        try:
            dom_sid = info["Domain"].get("LogonDomainId")
            gc = int(kvi["GroupCount"])
            print(f"    {Colors.GREEN}Groups ({gc}):{Colors.RESET}")
            
            if gc > 0 and kvi["GroupIds"]:
                gids = kvi["GroupIds"]
                for i in range(gc):
                    try:
                        rid = int(gids[i]["RelativeId"])
                        attrs = int(gids[i]["Attributes"])
                        sid = join_domain_sid_and_rid(dom_sid, rid) if dom_sid else None
                        group_name = RID_NAME_MAP.get(rid, "")
                        
                        info["Groups"].append({
                            "RID": rid, 
                            "SID": sid, 
                            "Attributes": attrs,
                            "Name": group_name
                        })
                        
                        name_part = f" ({group_name})" if group_name else ""
                        attrs_str = flags_to_names_map(attrs, GROUP_ATTRS)
                        print(f"      RID: {Colors.YELLOW}{rid}{Colors.RESET}, SID: {Colors.CYAN}{sid}{Colors.RESET}{name_part}")
                        print(f"        Attributes: {Colors.GREEN}{attrs_str}{Colors.RESET}")
                    except Exception as e:
                        if str(e) not in ["0", "'string'", "None"]:
                               print(f"    {Colors.DIM}Could not read LogonScript{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading groups: {e}{Colors.RESET}")

        try:
            sc = int(kvi["SidCount"])
            print(f"    {Colors.GREEN}Extra SIDs ({sc}):{Colors.RESET}")
            
            if sc > 0 and kvi["ExtraSids"]:
                extra_sids = kvi["ExtraSids"]
                for i in range(sc):
                    try:
                        esid = extra_sids[i]["Sid"].formatCanonical()
                        attrs = int(extra_sids[i]["Attributes"])
                        info["ExtraSids"].append({"SID": esid, "Attributes": attrs})
                        
                        attrs_str = flags_to_names_map(attrs, SE_GROUP_ATTRS)
                        print(f"      SID: {Colors.CYAN}{esid}{Colors.RESET}")
                        print(f"        Attributes: {Colors.GREEN}{attrs_str}{Colors.RESET}")
                    except Exception as e:
                        print(f"      {Colors.RED}Error reading extra SID {i}: {e}{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading extra SIDs: {e}{Colors.RESET}")

        try:
            rgc = int(kvi["ResourceGroupCount"])
            print(f"    {Colors.GREEN}Resource Groups ({rgc}):{Colors.RESET}")
            
            if rgc > 0:
                base_sid = None
                if kvi["ResourceGroupDomainSid"] and kvi["ResourceGroupDomainSid"] != b'':
                    base_sid = kvi["ResourceGroupDomainSid"].formatCanonical()
                    info["Domain"]["ResourceGroupDomainSid"] = base_sid
                    print(f"      Resource Group Domain SID: {Colors.CYAN}{base_sid}{Colors.RESET}")
                else:
                    base_sid = info["Domain"].get("LogonDomainId")

                if kvi["ResourceGroupIds"]:
                    rgids = kvi["ResourceGroupIds"]
                    for i in range(rgc):
                        try:
                            rid = int(rgids[i]["RelativeId"])
                            attrs = int(rgids[i]["Attributes"])
                            sid = join_domain_sid_and_rid(base_sid, rid) if base_sid else None
                            group_name = RID_NAME_MAP.get(rid, "")
                            
                            info["ResourceGroups"].append({
                                "RID": rid, 
                                "SID": sid, 
                                "Attributes": attrs,
                                "Name": group_name
                            })
                            
                            name_part = f" ({group_name})" if group_name else ""
                            attrs_str = flags_to_names_map(attrs, GROUP_ATTRS)
                            print(f"      RID: {Colors.YELLOW}{rid}{Colors.RESET}, SID: {Colors.CYAN}{sid}{Colors.RESET}{name_part}")
                            print(f"        Attributes: {Colors.GREEN}{attrs_str}{Colors.RESET}")
                        except Exception as e:
                            print(f"      {Colors.RED}Error reading resource group {i}: {e}{Colors.RESET}")
        except Exception as e:
            print(f"    {Colors.RED}Error reading resource groups: {e}{Colors.RESET}")

        additional_fields = [
            ("LogonScript", "Logon Script"),
            ("ProfilePath", "Profile Path"), 
            ("HomeDirectory", "Home Directory"),
            ("HomeDirectoryDrive", "Home Directory Drive"),
            ("SubAuthStatus", "SubAuth Status"),
        ]

        for field_name, display_name in additional_fields:
            try:
                if hasattr(kvi, field_name):
                    field_value = getattr(kvi, field_name)
                    if field_value and hasattr(field_value, 'string'):
                        value = field_value.string
                        if value and value.strip():
                            info["User"][field_name] = value
                            print(f"    {Colors.GREEN}{display_name}: {Colors.CYAN}{value}{Colors.RESET}")
            except Exception as e:
                if "0" not in str(e) and "string" not in str(e):
                    print(f"    {Colors.RED}Error reading {field_name}: {e}{Colors.RESET}")

        try:
            if hasattr(kvi, "UserSessionKey") and kvi["UserSessionKey"]:
                session_key = bytes(kvi["UserSessionKey"])
                if session_key != b'\x00' * len(session_key):
                    info["User"]["UserSessionKey"] = session_key.hex()
                    print(f"    {Colors.GREEN}User Session Key: {Colors.CYAN}{session_key.hex()}{Colors.RESET}")
                else:
                    print(f"    {Colors.DIM}User Session Key: (empty - all zeros){Colors.RESET}")
        except Exception as e:
            if str(e) not in ["0", "'UserSessionKey'"]:
                print(f"    {Colors.RED}Error reading UserSessionKey: {e}{Colors.RESET}")

    except Exception as e:
        print(f"    {Colors.RED}PAC_LOGON_INFO parse failed: {e}{Colors.RESET}")
        return {"_error": f"PAC_LOGON_INFO parse failed: {e}"}
    
    return info


#################################################

def parse_gss_api_checksum(checksum_data: bytes):
    if len(checksum_data) < 24:
        return None
        
    krbtgt_pos = checksum_data.find(b'krbtgt')
    if krbtgt_pos >= 0:

        for i in range(max(0, krbtgt_pos - 100), krbtgt_pos):
            if checksum_data[i] == 0x30:  # SEQUENCE
                return extract_ticket_from_position(checksum_data, i)
    
    return None

##################################################

def extract_ticket_from_position(data: bytes, pos: int):
    if pos >= len(data) or data[pos] != 0x30:
        return None
   
    length_byte = data[pos + 1]
    if length_byte & 0x80: 
        length_bytes = length_byte & 0x7F
        if length_bytes <= 2:
            actual_length = 0
            for i in range(length_bytes):
                actual_length = (actual_length << 8) | data[pos + 2 + i]
            
            content_start = pos + 2 + length_bytes
            ticket_data = data[pos:content_start + actual_length]
            
            print(f"Found forwarded TGT ticket:")
            print(f"Size: {len(ticket_data)} bytes")
            print(f"Data: {ticket_data.hex()}")
            return ticket_data
    
    return None


##################################################
def parse_authenticator_with_cred(pt_a: bytes):
    try:
        from impacket.krb5.asn1 import Authenticator, KRB_CRED
        from pyasn1.codec.der import encoder as der_encoder

        auth, _ = der_decode(pt_a, asn1Spec=Authenticator())
        
        print(f"{GREEN}[+] Authenticator cname:{RESET}", str(auth['cname']))
        print(f"{GREEN}[+] Authenticator crealm:{RESET}", str(auth['crealm']))
        print(f"{GREEN}[+] Authenticator ctime:{RESET}", dt_str(str(auth['ctime'])),
              "usec:", int(auth['cusec']) if auth['cusec'].hasValue() else "<absent>")
        
        if auth['subkey'].hasValue():
            print(f"{GREEN}[+] Authenticator subkey etype:{RESET}", int(auth['subkey']['keytype']))
            print(f"{GREEN}[+] Authenticator subkey:{RESET}", bytes(auth['subkey']['keyvalue']).hex())
            
        if auth['seq-number'].hasValue():
            print(f"{GREEN}[+] Sequence number:{RESET}", int(auth['seq-number']))
        
        if auth['cksum'].hasValue():
            cksum = auth['cksum']
            cksum_type = int(cksum['cksumtype'])
            cksum_data = bytes(cksum['checksum'])
            
            print(f"{YELLOW}[+] Checksum type:{RESET} {cksum_type} (0x{cksum_type:x})")
            print(f"{YELLOW}[+] Checksum length:{RESET} {len(cksum_data)} bytes")
            
            if cksum_type == 0x8003:
                print(f"{CYAN}[!] Found GSS-API checksum - parsing for delegation data...{RESET}")
                
                if len(cksum_data) >= 24:
                    import struct
                    flags = struct.unpack('<I', cksum_data[20:24])[0]
                    print(f"{CYAN}[+] GSS-API Flags:{RESET} 0x{flags:08x}")
                    
                    if flags & 1:
                        print(f"{BOLD}{GREEN}[!] DELEGATION FLAG SET! Extracting KRB-CRED...{RESET}")
                        
                        if len(cksum_data) > 28:
                            krb_cred_data = cksum_data[28:]
                            print(f"{BOLD}{MAGENTA}[!] FOUND FORWARDED TGT IN KRB-CRED:{RESET}")
                            
                            try:
                                krb_cred, _ = der_decode(krb_cred_data, asn1Spec=KRB_CRED())
                                print(f"{GREEN}[+] KRB-CRED parsed successfully!{RESET}")
                                
                                if krb_cred['tickets'].hasValue():
                                    tickets = krb_cred['tickets']
                                    print(f"{GREEN}[+] Number of tickets in KRB-CRED:{RESET} {len(tickets)}")
                                    
                                    for i, ticket in enumerate(tickets):
                                        print(f"{YELLOW}[+] Ticket {i+1}:{RESET}")
                                        print(f"    Realm: {Colors.CYAN}{str(ticket['realm'])}{Colors.RESET}")
                                        sname = ticket['sname']
                                        snames = [str(x) for x in sname['name-string']]
                                        print(f"    Service: {Colors.CYAN}{'/'.join(snames)}{Colors.RESET}")
                                        
                                       
                                        raw_ticket_bytes = der_encoder.encode(ticket)
                                        print(f"    TGT Hex ({len(raw_ticket_bytes)} bytes): {Colors.DIM}{raw_ticket_bytes.hex()}{RESET}")
                                        
                                        if 'krbtgt' in '/'.join(snames).lower():
                                            print(f"{BOLD}{GREEN}    >>> THIS IS THE FORWARDED TGT!{RESET}")
                            
                            except Exception as e:
                                print(f"{RED}[!] Failed to parse KRB-CRED: {e}{RESET}")
                                print(f"{YELLOW}[!] Raw KRB-CRED data (hex):{RESET} {krb_cred_data.hex()}")
    
    except Exception as e:
        print("[*] Could not parse Authenticator:", e)


##################################################

def pretty_print_enc_ticket_part_and_pac(decrypted_enc_ticket_part_bytes: bytes):
    enc, _ = der_decode(decrypted_enc_ticket_part_bytes, asn1Spec=EncTicketPart())

    print(f"{Colors.BOLD}{Colors.MAGENTA}ENC Part Ticket:{Colors.RESET}")
    print("=====================")
    try:
        flags_int = int(enc['flags'])
    except Exception:
        try:
            bits = list(enc['flags'].asNumbers())
            v = 0
            for b in bits:
                v = (v << 1) | (1 if b else 0)
            flags_int = v
        except Exception:
            flags_int = None

    if flags_int is not None:
        names = flags_to_names_masked(flags_int)
        print(f"{Colors.YELLOW}Ticket Flags:{Colors.RESET} {Colors.CYAN}{', '.join(names)}{Colors.RESET}")
    else:
        print(f"{Colors.RED}Ticket Flags: (unavailable){Colors.RESET}")

    kt = int(enc['key']['keytype']); kv = bytes(enc['key']['keyvalue']).hex()
    print(f"{Colors.YELLOW}Session Key:{Colors.RESET} {Colors.CYAN}{kv}{Colors.RESET}, {Colors.CYAN}etype: {kt}{Colors.RESET}")
    print(f"{Colors.YELLOW}Realm:{Colors.RESET} {Colors.CYAN}{str(enc['crealm'])}{Colors.RESET}")

    cname = enc['cname']; nt = None
    try: nt = int(cname['name-type'])
    except Exception: pass
    cnames = [str(x) for x in cname['name-string']]
    print(f"{Colors.YELLOW}Client:{Colors.RESET} {Colors.CYAN}{'/'.join(cnames)}{Colors.RESET}")

    at = _fmt_gt(enc['authtime']) if enc['authtime'].hasValue() else "-"
    st = _fmt_gt(enc['starttime']) if enc['starttime'].hasValue() else "-"
    et = _fmt_gt(enc['endtime']) if enc['endtime'].hasValue() else "-"
    rt = _fmt_gt(enc['renew-till']) if enc['renew-till'].hasValue() else "-"
    print(f"{Colors.YELLOW}Authentication Time: {Colors.RESET}{Colors.CYAN}{at}{Colors.RESET}")
    print(f"{Colors.YELLOW}Starting Time: {Colors.RESET}{Colors.CYAN}{st}{Colors.RESET}")
    print(f"{Colors.YELLOW}End Time: {Colors.RESET}{Colors.CYAN}{et}{Colors.RESET}")
    print(f"{Colors.YELLOW}Renew Till: {Colors.RESET}{Colors.CYAN}{rt}{Colors.RESET}")

    if 'authorization-data' in enc and enc['authorization-data'].hasValue():
        print("  ")
        pac_bytes = None
        for entry in enc['authorization-data']:
            ad_data = bytes(entry['ad-data'])
            try:
                pac_bytes = extract_pac_bytes_from_ad(ad_data)
                break
            except Exception:
                continue

        if pac_bytes is None:
            print(f"{Colors.YELLOW}(No PAC found inside AuthorizationData){Colors.RESET}")
            return

        try:
            pac = parse_pac_raw(pac_bytes)
            if PAC_VERBOSE:
                pac_coverage_report(pac_bytes, pac)
        except Exception as e:
            print(f"{Colors.RED}[!] PAC parse failed: {e}{Colors.RESET}")
            return

        print(f"{Colors.BOLD}{Colors.CYAN}PAC Full Analysis:{Colors.RESET}")
        print("====================")
        
        for e in pac['entries']:
            t = e['type']
            data = e['data']
            if t == 1:  
                li = parse_pac_logon_info(data)
                if "_error" in li:
                    print(f"    {Colors.RED}Error: {li['_error']}{Colors.RESET}")
                else:
                    user = li.get("User", {})
                    domain = li.get("Domain", {})
                    
                    if user.get('UserName'):
                        print(f"{Colors.YELLOW}[*] User:{Colors.RESET}{Colors.CYAN} {user['UserName']}{Colors.RESET}")
                    if user.get('FullName'):
                        print(f"{Colors.YELLOW}[*] Full Name:{Colors.RESET} {Colors.CYAN}{user['FullName']}{Colors.RESET}")
                    if user.get('RID'):
                        print(f"{Colors.YELLOW}[*] RID:{Colors.RESET} {Colors.CYAN}{user['RID']}{Colors.RESET}")
                    if user.get('UserSid'):
                        print(f"{Colors.YELLOW}[*] UserSid:{Colors.RESET}{Colors.CYAN}{user['UserSid']}{Colors.RESET}")
                    if user.get('LogonCount') is not None:
                        print(f"{Colors.YELLOW}[*] Logon Count:{Colors.RESET} {Colors.CYAN}{user['LogonCount']}{Colors.RESET}")
                    if user.get('BadPasswordCount') is not None:
                        print(f"{Colors.YELLOW}[*] Bad Password Count:{Colors.RESET} {Colors.CYAN}{user['BadPasswordCount']}{Colors.RESET}")
                    if user.get('UserAccountControl') is not None:
                        uac = user['UserAccountControl']
                        print(f"{Colors.YELLOW}[*] User Account Control:{Colors.RESET} {Colors.CYAN}0x{uac:x}{Colors.RESET} ({Colors.CYAN}{flags_to_names_map(uac, UAC_FLAGS)}{Colors.RESET})")
                    
                    if domain.get('LogonDomainName'):
                        print(f"{Colors.YELLOW}[*] Domain:{Colors.RESET} {Colors.CYAN}{domain['LogonDomainName']}{Colors.RESET}")
                    if domain.get('LogonDomainId'):
                        print(f"{Colors.YELLOW}[*] Domain SID:{Colors.RESET} {Colors.CYAN}{domain['LogonDomainId']}{Colors.RESET}")
                    if domain.get('PrimaryGroupId'):
                        pid = domain['PrimaryGroupId']
                        pname = RID_NAME_MAP.get(pid, "")
                        print(f"{Colors.YELLOW}[*] Primary Group:{Colors.RESET} {Colors.CYAN}{pid}{Colors.RESET}{' (' + pname + ')' if pname else ''}")
                    
                    groups = li.get("Groups", [])
                    if groups:
                        print(f"{Colors.GREEN}[*] Groups {Colors.RESET} ({len(groups)}):")
                        for g in groups:
                            name_part = f" ({Colors.GREEN}{g.get('Name')}{Colors.RESET})" if g.get('Name') else ""
                            attrs_str = flags_to_names_map(g.get('Attributes', 0), GROUP_ATTRS)
                            print(f"  {Colors.YELLOW}[->] RID:{Colors.RESET} {Colors.CYAN}{g.get('RID')}{Colors.RESET}, SID: {Colors.CYAN}{g.get('SID')}{Colors.RESET}{name_part}")
                            print(f"  {Colors.YELLOW}[->] Attributes:{Colors.RESET} {Colors.CYAN}{attrs_str}{Colors.RESET}")
                    
                    extra_sids = li.get("ExtraSids", [])
                    if extra_sids:
                        print(f"{Colors.GREEN}[*] ExtraSids {Colors.RESET}({len(extra_sids)}):")
                        for es in extra_sids:
                            attrs_str = flags_to_names_map(es.get('Attributes', 0), SE_GROUP_ATTRS)
                            print(f"  {Colors.YELLOW}[->] SID:{Colors.RESET} {Colors.CYAN}{es.get('SID')}{Colors.RESET}")
                            print(f"  {Colors.YELLOW}[->] Attributes:{Colors.RESET} {Colors.CYAN}{attrs_str}{Colors.RESET}")
                    
                    resource_groups = li.get("ResourceGroups", [])
                    if resource_groups:
                        print(f"{Colors.GREEN}[*] ResourceGroups {Colors.RESET} ({len(resource_groups)}):")
                        for rg in resource_groups:
                            name_part = f" ({Colors.GREEN}{rg.get('Name')}{Colors.RESET})" if rg.get('Name') else ""
                            attrs_str = flags_to_names_map(rg.get('Attributes', 0), GROUP_ATTRS)
                            print(f"  {Colors.YELLOW}[->] RID: {Colors.RESET} {Colors.CYAN}{rg.get('RID')}{Colors.RESET}, SID: {Colors.CYAN}{rg.get('SID')}{Colors.RESET}{name_part}")
                            print(f"  {Colors.YELLOW}[->] Attributes:{Colors.RESET} {Colors.CYAN}{attrs_str}{Colors.RESET}")
                    
                    times = li.get("Times", {})
                    if times:
                        print(f"{Colors.GREEN}[*] Times: {Colors.RESET}")
                        for time_name, nt_time in times.items():
                            time_str = _nt_to_dt_str(nt_time)
                            print(f"{Colors.YELLOW}[->] {time_name}:{Colors.RESET}  {Colors.CYAN}{time_str}{Colors.RESET}")
            
            elif t == 6:
                print(f"{Colors.GREEN}PAC_SERVER_CHECKSUM{Colors.RESET}")
                sig_info = parse_pac_signature(data)
                for k, v in sig_info.items():
                    print(f"    {k}: {Colors.CYAN}{v}{Colors.RESET}")
            
            elif t == 7: 
                print(f"{Colors.GREEN}PAC_PRIVSVR_CHECKSUM (KDC){Colors.RESET}")
                sig_info = parse_pac_signature(data)
                for k, v in sig_info.items():
                    print(f"    {k}: {Colors.CYAN}{v}{Colors.RESET}")
            
            elif t == 10:  
                print(f"{Colors.GREEN}PAC_CLIENT_INFO{Colors.RESET}")
                ci = parse_pac_client_info(data)
                for k, v in ci.items():
                    print(f"    {k}: {Colors.CYAN}{v}{Colors.RESET}")
            
            elif t == 12:  
                print(f"{Colors.GREEN}PAC_UPN_DNS_INFO{Colors.RESET}")
                upn = parse_pac_upn_dns_info(data)
                for k, v in upn.items():
                    print(f"    {k}: {Colors.CYAN}{v}{Colors.RESET}")

            elif t == 16: 
                print(f"  {Colors.GREEN}PAC_CREDENTIAL_INFO{Colors.RESET}")
                if len(data) >= 8:
                    version = unpack_from("<I", data, 0)[0]
                    type_or_etype = unpack_from("<I", data, 4)[0]
                    blob = data[8:]
                    
                    print(f"    Version: {Colors.CYAN}0x{version:08x}{Colors.RESET}")
                    print(f"    Type/Etype: {Colors.CYAN}{type_or_etype} (0x{type_or_etype:08x}){Colors.RESET}")
                    print(f"    Credentials Blob Size: {Colors.CYAN}{len(blob)} bytes{Colors.RESET}")
                    print(f"    Credentials Blob (hex): {Colors.CYAN}{blob.hex()}{Colors.RESET}")

            elif t == 17: 
                print(f"{Colors.GREEN}PAC_ATTRIBUTES_INFO{Colors.RESET}")
                attr = parse_pac_attributes_info(data)
                for k, v in attr.items():
                    print(f"    {k}: {Colors.CYAN}{v}{Colors.RESET}")
            
            elif t == 18: 
                print(f"{Colors.GREEN}PAC_REQUESTOR{Colors.RESET}")
                req = parse_pac_requestor(data)
                for k, v in req.items():
                    print(f"    {k}: {Colors.CYAN}{v}{Colors.RESET}")

            elif t == 19:   
                print(f"  {Colors.GREEN}PAC_EXTENDED_KDC_CHECKSUM{Colors.RESET}")
                if len(data) >= 4:
                    checksum_type = unpack_from("<I", data, 0)[0]
                    checksum = data[4:]
                    print(f"    ChecksumType: {Colors.CYAN}0x{checksum_type:08x}{Colors.RESET}")
                    print(f"    Extended Checksum: {Colors.CYAN}{checksum.hex()}{Colors.RESET}")
                    print(f"    {Colors.DIM}(Enhanced KDC signature for additional security){Colors.RESET}")
                        
            elif t == 20: 
                print(f"{Colors.GREEN}PAC_CLAIMS_INFO{Colors.RESET}")
                claims = parse_pac_claims_info(data)
                for k, v in claims.items():
                    print(f"    {k}: {Colors.CYAN}{v}{Colors.RESET}")
            
            else:
                print(f"{Colors.YELLOW}Unknown PAC type {t} (size: {len(data)} bytes){Colors.RESET}")
                if len(data) <= 100:
                    print(f"    Hex: {Colors.DIM}{data.hex()}{Colors.RESET}")
                else:
                    print(f"    Hex: {Colors.DIM}{data.hex()[:100]}...{Colors.RESET}")


##################################################

#COLORRORORORRRRRSSS

RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
MAGENTA = "\033[35m"
CYAN    = "\033[36m"
WHITE   = "\033[37m"
RESET   = "\033[0m"

BOLD      = "\033[1m"
DIM       = "\033[2m"
UNDERLINE = "\033[4m"
BLINK     = "\033[5m"
HIDDEN    = "\033[8m"

########################################################

def dt_str(pat: str) -> str:
    try:
        dt = datetime.strptime(pat, '%Y%m%d%H%M%SZ')
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return pat


########################################################
def decrypt(etype: int, key_hex: str, usage: int, cipher_hex: str) -> bytes:
    key = Key(etype, unhexlify(key_hex))
    crypto = _enctype_table[etype]
    return crypto.decrypt(key, usage, unhexlify(cipher_hex))

########################################################



 
########################################################
  
def analyze_rpc_data(data: bytes):
    if len(data) < 16:
        return
    
    print(f"{Colors.CYAN}RPC Analysis:{Colors.RESET}")
    
   
    first_dword = int.from_bytes(data[:4], 'little')
    print(f"  First DWORD (LE): 0x{first_dword:08x}")
    
   
    rpc_signatures = {
        0x05000000: "DCE/RPC Request",
        0x05000002: "DCE/RPC Response", 
        0x05000003: "DCE/RPC Fault",
        0x050000c0: "DCE/RPC Request (fragmented)",
        0x050000c2: "DCE/RPC Response (fragmented)",
    }
    
    signature = first_dword & 0xFF0000FF
    if signature in rpc_signatures:
        print(f"  Detected: {rpc_signatures[signature]}")
    
  
    try:
        version = data[0]
        ptype = data[1]
        flags = data[2] 
        drep = data[3]
        frag_len = int.from_bytes(data[4:6], 'little')
        auth_len = int.from_bytes(data[6:8], 'little')
        call_id = int.from_bytes(data[8:12], 'little')
        
        print(f"  RPC Version: {version}")
        print(f"  Packet Type: {ptype}")
        print(f"  Flags: 0x{flags:02x}")
        print(f"  Data Rep: 0x{drep:02x}")
        print(f"  Fragment Length: {frag_len}")
        print(f"  Auth Length: {auth_len}")
        print(f"  Call ID: 0x{call_id:08x}")
        

        if frag_len == len(data):
            print(f"[+] Fragment length matches data length")
        else:
            print(f"[-] Fragment length mismatch (expected {frag_len}, got {len(data)})")
            
    except Exception as e:
        print(f"  Could not parse as RPC header: {e}")
    
    # Look for printable strings
    text = data.decode('ascii', errors='ignore')
    printable_chars = sum(1 for c in text if c.isprintable() and c != ' ')
    print(f"  Printable chars: {printable_chars}/{len(data)} ({printable_chars/len(data)*100:.1f}%)")


########################################################

def parse_args():
    p = argparse.ArgumentParser(prog="Kerberos.py", description="Kerberos helper")
    sub = p.add_subparsers(dest="mode", required=True)

    # AS-REQ 
    asreq = sub.add_parser("as-req", help="AS-REQ    : Authentication Request packet ( Client -> KDC )")
    src = asreq.add_mutually_exclusive_group(required=True)
    src.add_argument("--padata-value", help="HEX Stream value of padata-value (Pre Authentication Data) 'PA-DATA pA-ENC-TIMESTAMP'")
    src.add_argument("--cipher", help="HEX Stream value of cipher in 'PA-DATA pA-ENC-TIMESTAMP'")
    asreq.add_argument("--key", required=True, help="rc4_hmac | aaes256_cts_hmac_sha1 | aes128_cts_hmac_sha1 of user clinet")
    asreq.add_argument("--etype", type=int, default="23", help="Use This argument only with --cipher argument, the default is 23")

    # AS-REP 
    asrep = sub.add_parser("as-rep", help="AS-REP    : Authentication Reply packet ( KDC-> Client )")
    tgt = asrep.add_argument_group("TGT enc-part")
    tgt_src = tgt.add_mutually_exclusive_group()
    tgt_src.add_argument("--tgt-ticket", help="HEX Stream value cipher of TGT enc-part")
    tgt.add_argument("--krbtgt-key", help="Using krbtgt service account's aes256_cts_hmac_sha1 hash for decrypting TGT | some cases you will need the rc4_hmac hash")
    tgt.add_argument("--ticket-etype", type=int, default=18, help="Use this --etype argument with value of 18(The Default) - for aes256_cts_hmac_sha1 | 17  - for aes128_cts_hmac_sha1 | 23 - for rc4_hmac")

    cl = asrep.add_argument_group("Client enc-part")
    cl_src = cl.add_mutually_exclusive_group()
    cl_src.add_argument("--client-cipher", help="HEX Stream cipher of client enc-part")
    cl.add_argument("--client-key", help="rc4_hmac | aes256_cts_hmac_sha1 | aes128_cts_hmac_sha1 of user clinet")
    cl.add_argument("--client-etype", type=int, default=23, help="Use this --etype argument with value of 23 for rc4_hmac(The Default) |  18 - for aes256_cts_hmac_sha1 | 17 - for aes128_cts_hmac_sha1")

    # TGS-REQ
    tgsreq = sub.add_parser("tgs-req", help="TGS-REQ   : Ticket Granting Serivce Request packet ( Client -> KDC ) ")
    tgs = tgsreq.add_argument_group("TGT enc-part")
    tgs_src_tkt = tgs.add_mutually_exclusive_group()
    tgs_src_tkt.add_argument("--tgt-ticket", help="HEX Stream cipher of TGT enc-part (from AS-REP)")
    tgs.add_argument("--tgt-ticket-key", help="Using krbtgt service account's aes256_cts_hmac_sha1 hash for decrypting TGT | some cases you will need the rc4_hmac hash")
    tgs.add_argument("--tgt-ticket-etype", type=int, default=18, help="Use this --etype argument with value of 18(The Default) - for aes256_cts_hmac_sha1 | 17 -  for aes128_cts_hmac_sha1 | 23 - for rc4_hmac")

    tgs_auth = tgsreq.add_argument_group("Authenticator enc-part")
    tgs_src_auth = tgs_auth.add_mutually_exclusive_group()
    tgs_src_auth.add_argument("--authenticator-cipher", help="HEX cipher of AP-REQ authenticator")
    tgs_auth.add_argument("--session-key", help="Using Session Key from AS-REP packet (recived from KDC)")
    tgs_auth.add_argument("--authenticator-etype", type=int, default=23, help="Use this --etype argument with value of 23(The Default), in some cases the value will be 18 if the session key is aes256_cts_hmac_sha1..")

    # TGS-REP
    tgsrep = sub.add_parser("tgs-rep", help="TGS-REP    : Ticket Granting Serivce Reply packet ( KDC -> Client ) ")
    grp_t = tgsrep.add_argument_group("TGS enc-part (ticket)")
    grp_t_src = grp_t.add_mutually_exclusive_group()
    grp_t_src.add_argument("--tgs-ticket", help="HEX cipher of service ticket enc-part")
    grp_t.add_argument("--tgs-service-key", help="Using service account's aes256_cts_hmac_sha1 hash for decrypting TGS | some cases you will need the rc4_hmac has")
    grp_t.add_argument("--tgs-ticket-etype", type=int, default=18, help="Use this --etype argument with value of 18(The Default) - for aes256_cts_hmac_sha1 | 17 -  for aes128_cts_hmac_sha1 | 23 - for rc4_hmac")

    grp_c = tgsrep.add_argument_group("Client enc-part (EncTGSRepPart)")
    grp_c_src = grp_c.add_mutually_exclusive_group()
    grp_c_src.add_argument("--encpart-cipher", help="HEX Stream value cipher of EncTGSRepPart")
    grp_c.add_argument("--session-key", help="Using Session Key from AS-REP packet (recived from KDC)")
    grp_c.add_argument("--encpart-etype", type=int, default=23, help="Use this --etype argument with value of 23(The Default), in some cases the value will be 18 if the session key is aes256_cts_hmac_sha1..")

    # AP-REQ 
    service1 = sub.add_parser("ap-req", help="AP_REQ:   Application Request packet ( Client -> Application Service )")
    grp_t = service1.add_argument_group("TGS enc-part (ticket)")
    grp_t_src = grp_t.add_mutually_exclusive_group()
    grp_t_src.add_argument("--tgs-ticket", help="HEX Stream value of cipher service ticket enc-part")
    grp_t.add_argument("--tgs-service-key", help="Using service account's aes256_cts_hmac_sha1 hash for decrypting TGS | some cases you will need the rc4_hmac has")
    grp_t.add_argument("--tgs-ticket-etype", type=int, default=23, help="Use this --etype argument with value of 18(The Default) - for aes256_cts_hmac_sha1 | 17 - for aes128_cts_hmac_sha1 | 23 - for rc4_hmac")

    grp_c = service1.add_argument_group("Client enc-part (EncTGSRepPart)")
    grp_c_src = grp_c.add_mutually_exclusive_group()
    grp_c_src.add_argument("--authenticator-cipher", help="HEX Stream cipher value of EncTGSRepPart")
    grp_c.add_argument("--session-key", help="Using Session Key from TGS-REP packet (recived from KDC)")
    grp_c.add_argument("--authenticator-etype", type=int, default=18, help="Use this --etype argument with value of 18(The Default), in some cases the value will be 23 if the session key is rc4_hmac..")    

    # AP-REP
    service2 = sub.add_parser("ap-rep", help="AP_RP:   Application Reply packet ( Application Service -> Client )" )
    grp_c = service2.add_argument_group("Client enc-part (EncTGSRepPart)")
    grp_c_src = grp_c.add_mutually_exclusive_group()
    grp_c_src.add_argument("--encpart-cipher", help="HEX Stream cipher value of EncTGSRepPart")
    grp_c.add_argument("--session-key", help="Using Session Key from TGS-REP packet (recived from KDC)")
    grp_c.add_argument("--encpart-etype", type=int, default=23, help="Use this --etype argument with value of 18(The Default), in some cases the value will be 23 if the session key is rc4_hmac..")   


    return p.parse_args()

########################################################

def main():
    args = parse_args()

#AS-REQ  
    if args.mode == "as-req":
        if args.padata_value:
            ed, _ = der_decode(unhexlify(args.padata_value), asn1Spec=EncryptedData())
            etype = int(ed['etype']) 
            cipher_hex = bytes(ed['cipher']).hex()
        else:
            if args.etype is None:
                print("[!] Please use --etype and chose 17/18/23", file=sys.stderr)
                sys.exit(1)
            etype = args.etype
            cipher_hex = args.cipher

        pt = decrypt(etype, args.key, 1, cipher_hex)
        print("")
        print(f"{MAGENTA}[+]Decrypted hex{RESET}: {pt.hex()}")
        try:
            ts, _ = der_decode(pt, asn1Spec=PA_ENC_TS_ENC())
            print(f"{MAGENTA}[+]Decoded Pre-Authentication TimeStamp{RESET}:", dt_str(str(ts['patimestamp'])))
        except Exception as e:
            print("[*] Decrypted but could not parse PA-ENC-TS-ENC:", e); sys.exit(2)
        return

    # AS-REP 
    if args.mode == "as-rep":
        ticket_cipher_hex   = args.tgt_ticket
        ticket_etype        = args.ticket_etype
        encpart_cipher_hex  = args.client_cipher
        encpart_etype       = args.client_etype
        if not any([ticket_cipher_hex, encpart_cipher_hex]):
            print("[!] Provide at least one of: --tgt-ticket or --client-cipher"); sys.exit(1)
        if ticket_cipher_hex:
            if not args.krbtgt_key:
                print("[!] --krbtgt-key is required to decrypt TGT enc-part"); sys.exit(1)
            pt_t = decrypt(ticket_etype, args.krbtgt_key, 2, ticket_cipher_hex)
            print("")
            print(f"{MAGENTA}[+] TGT Decrypted: decrypted hex{RESET}: {pt_t.hex()}")
            pretty_print_enc_ticket_part_and_pac(pt_t)
            try:
                enc_tkt, _ = der_decode(pt_t, asn1Spec=EncTicketPart())
                kt = int(enc_tkt['key']['keytype'])
                kv = bytes(enc_tkt['key']['keyvalue']).hex()
                print(f"{GREEN}[+] EncTicketPart key etype{RESET}: {kt}")
                print(f"{GREEN}[+] EncTicketPart session key{RESET}: {kv}")
            except Exception as e:
                print("[*] Could not parse EncTicketPart:", e)
        if encpart_cipher_hex:
            if not args.client_key:
                print("[!] --client-key is required to decrypt client enc-part"); sys.exit(1)
            pt_c = decrypt(encpart_etype, args.client_key, 3, encpart_cipher_hex)
            print("")
            print(f"{MAGENTA}[+] client enc-part decrypted hex:{RESET} {pt_c.hex()}")
            try:
                encp, _ = der_decode(pt_c, asn1Spec=EncASRepPart())
                
              
                kt = int(encp['key']['keytype'])
                kv = bytes(encp['key']['keyvalue']).hex()
                print(f"{GREEN}[+] AS-REP session key etype:{RESET} {kt}")
                print(f"{GREEN}[+] AS-REP session key:{RESET} {kv}")
                
      
                if encp['nonce'].hasValue():
                    nonce_val = int(encp['nonce'])
                    print(f"{YELLOW}[+] nonce:{RESET} 0x{nonce_val:08x} ({nonce_val})")
                
                if encp['key-expiration'].hasValue():
                    print(f"{YELLOW}[+] key-expiration:{RESET}", dt_str(str(encp['key-expiration'])))
                
                if encp['flags'].hasValue():
                    flags_int = int(encp['flags'])  
                    flag_names = flags_to_names_masked(flags_int)
                    print(f"{YELLOW}[+] flags:{RESET} 0x{flags_int:08x} ({flag_names})")
                
                if encp['last-req'].hasValue():
                    print(f"{YELLOW}[+] last-req:{RESET} Last requests available")
                
                print(f"{YELLOW}[+] srealm:{RESET}", str(encp['srealm']))
                print(f"{YELLOW}[+] sname:{RESET}", str(encp['sname']))
                
            
                if encp['authtime'].hasValue():   print(f"{YELLOW}[+] authtime:{RESET}",   dt_str(str(encp['authtime'])))
                if encp['starttime'].hasValue():  print(f"{YELLOW}[+] starttime:{RESET}",  dt_str(str(encp['starttime'])))
                if encp['endtime'].hasValue():    print(f"{YELLOW}[+] endtime:{RESET}",    dt_str(str(encp['endtime'])))
                if encp['renew-till'].hasValue(): print(f"{YELLOW}[+] renew-till:{RESET}", dt_str(str(encp['renew-till'])))
                
            except Exception as e:
                print("[*] Could not parse EncASRepPart:", e)
        return



# TGS-REQ
    if args.mode == "tgs-req":
        ticket_cipher_hex = args.tgt_ticket
        ticket_etype      = args.tgt_ticket_etype
        auth_cipher_hex   = args.authenticator_cipher 
        auth_etype        = args.authenticator_etype

        if not any([ticket_cipher_hex, auth_cipher_hex]):
            print("[!] Provide --tgt-ticket and/or --authenticator-cipher."); sys.exit(1)

        if ticket_cipher_hex:
            if not args.tgt_ticket_key:
                print("[!] --tgt-ticket-key is required to decrypt ticket.enc-part"); sys.exit(1)
            pt_t = decrypt(ticket_etype, args.tgt_ticket_key, 2, ticket_cipher_hex)
            print("")
            print(f"{MAGENTA}[+] TGT Decrypted hex:{RESET} {pt_t.hex()}")
            pretty_print_enc_ticket_part_and_pac(pt_t)
            try:
                enc_tkt, _ = der_decode(pt_t, asn1Spec=EncTicketPart())
                kt = int(enc_tkt['key']['keytype'])
                kv = bytes(enc_tkt['key']['keyvalue']).hex()
                print(f"{GREEN}[+] EncTicketPart key etype:{RESET} {kt}")
                print(f"{GREEN}[+] TGT session key:{RESET} {kv}")
            except Exception as e:
                print("[*] Could not parse EncTicketPart:", e)

        if auth_cipher_hex:
            if not args.session_key:
                print("[!] --session-key (AS-REP session key) is required to decrypt authenticator"); sys.exit(1)
            pt_a = decrypt(auth_etype, args.session_key, 7, auth_cipher_hex)
            print("")
            print(f"{MAGENTA}[+] Authenticator Decrypted{RESET}: {pt_a.hex()}")
            try:
                auth, _ = der_decode(pt_a, asn1Spec=Authenticator())
                print(f"{GREEN}[+] Authenticator cname:{RESET}", str(auth['cname']))
                print(f"{GREEN}[+] Authenticator crealm:{RESET}", str(auth['crealm']))
                print(f"{GREEN}[+] Authenticator ctime:{RESET}", dt_str(str(auth['ctime'])),
                    "usec:", int(auth['cusec']) if auth['cusec'].hasValue() else "<absent>")
                if auth['subkey'].hasValue():
                    print(f"{GREEN}[+] Authenticator subkey etype:{RESET}", int(auth['subkey']['keytype']))
                    print(f"{GREEN}[+] Authenticator subkey:{RESET}", bytes(auth['subkey']['keyvalue']).hex())
                if auth['seq-number'].hasValue():
                    print(f"{GREEN}[+] Sequence number:{RESET}", int(auth['seq-number']))
            except Exception as e:
                print("[*] Could not parse Authenticator:", e)
        return


#TGS-REP
    if args.mode == "tgs-rep":
        ticket_cipher_hex   = args.tgs_ticket
        ticket_etype        = args.tgs_ticket_etype
        encpart_cipher_hex  = args.encpart_cipher
        encpart_etype       = args.encpart_etype

        if not any([ticket_cipher_hex, encpart_cipher_hex]):
            print("[!] Provide --tgs-ticket and/or --encpart-cipher."); sys.exit(1)

        if ticket_cipher_hex:
            if not args.tgs_service_key:
                print("[!] --tgs-service-key is required to decrypt service ticket enc-part"); sys.exit(1)
            pt_t = decrypt(ticket_etype, args.tgs_service_key, 2, ticket_cipher_hex)
            print("")
            print(f"{MAGENTA}[+] TGS Decrypted hex:{RESET} {pt_t.hex()}")
            pretty_print_enc_ticket_part_and_pac(pt_t)
            try:
                enc_tkt, _ = der_decode(pt_t, asn1Spec=EncTicketPart())
                skt = int(enc_tkt['key']['keytype'])
                skv = bytes(enc_tkt['key']['keyvalue']).hex()
                print(f"{GREEN}[+] Service ticket session key etype:{RESET} {skt}")
                print(f"{GREEN}[+] Service ticket session key:{RESET} {skv}")
            except Exception as e:
                print("[*] Could not parse EncTicketPart:", e)

        if encpart_cipher_hex:
            reply_key = args.session_key
            if not reply_key:
                print("[!] Provide --session-key (reply key) to decrypt TGS-REP enc-part"); sys.exit(1)
            pt_c = decrypt(encpart_etype, reply_key, 8, encpart_cipher_hex) 
            print("")
            print(f"{MAGENTA}[+] TGS-REP enc-part decrypted hex:{RESET} {pt_c.hex()}")
            
            try:
                encp, _ = der_decode(pt_c, asn1Spec=EncTGSRepPart())
                kt = int(encp['key']['keytype'])
                kv = bytes(encp['key']['keyvalue']).hex()
                print(f"{GREEN}[+] TGS-REP session key etype:{RESET} {kt}")
                print(f"{GREEN}[+] TGS-REP session key:{RESET} {kv}")
                if encp['srealm'].hasValue():    print(f"{YELLOW}[+] srealm:{RESET}",    str(encp['srealm']))
                if encp['sname'].hasValue():     print(f"{YELLOW}[+] sname:{RESET}",     str(encp['sname']))
                if encp['authtime'].hasValue():  print(f"{YELLOW}[+] authtime:{RESET}",  dt_str(str(encp['authtime'])))
                if encp['starttime'].hasValue(): print(f"{YELLOW}[+] starttime:{RESET}", dt_str(str(encp['starttime'])))
                if encp['endtime'].hasValue():   print(f"{YELLOW}[+] endtime:{RESET}",   dt_str(str(encp['endtime'])))
                if encp['renew-till'].hasValue():print(f"{YELLOW}[+] renew-till:{RESET}",dt_str(str(encp['renew-till'])))
            except Exception as e:
                print("[*] Could not parse EncTGSRepPart:", e)
        return

    # AP-REQ
    if args.mode == "ap-req":
        tgs_cipher_hex = args.tgs_ticket
        tgs_etype = args.tgs_ticket_etype
        auth_cipher_hex = args.authenticator_cipher
        auth_etype = args.authenticator_etype

        if not any([tgs_cipher_hex, auth_cipher_hex]):
            print("[!] Provide --tgs-ticket and/or --authenticator-cipher."); sys.exit(1)


        if tgs_cipher_hex:
            if not args.tgs_service_key:
                print("[!] --service-key is required to decrypt TGS enc-part"); sys.exit(1)
            pt_t = decrypt(tgs_etype, args.tgs_service_key, 2, tgs_cipher_hex)
            print("")
            print(f"{MAGENTA}[+] TGS (Service Ticket) Decrypted hex:{RESET} {pt_t.hex()}")
            
            
            try:
                enc_tkt, _ = der_decode(pt_t, asn1Spec=EncTicketPart())
                skt = int(enc_tkt['key']['keytype'])
                skv = bytes(enc_tkt['key']['keyvalue']).hex()
                print(f"{GREEN}[+] Service session key etype:{RESET} {skt}")
                print(f"{GREEN}[+] Service session key:{RESET} {skv}")
                pretty_print_enc_ticket_part_and_pac(pt_t)
            except Exception as e:
                print("[*] Could not parse EncTicketPart:", e)

        if auth_cipher_hex:
            if not args.session_key:
                print("[!] --session-key (from TGS-REP) is required to decrypt authenticator"); sys.exit(1)
            pt_a = decrypt(auth_etype, args.session_key, 11, auth_cipher_hex) 
            print("")
            print(f"{MAGENTA}[+] AP-REQ Authenticator Decrypted:{RESET} {pt_a.hex()}")
            parse_authenticator_with_cred(pt_a)

            try:
                auth, _ = der_decode(pt_a, asn1Spec=Authenticator())
                print(f"{GREEN}[+] Authenticator cname:{RESET}", str(auth['cname']))
                print(f"{GREEN}[+] Authenticator crealm:{RESET}", str(auth['crealm']))
                print(f"{GREEN}[+] Authenticator ctime:{RESET}", dt_str(str(auth['ctime'])),
                    "usec:", int(auth['cusec']) if auth['cusec'].hasValue() else "<absent>")
                if auth['subkey'].hasValue():
                    print(f"{GREEN}[+] Authenticator subkey etype:{RESET}", int(auth['subkey']['keytype']))
                    print(f"{GREEN}[+] Authenticator subkey:{RESET}", bytes(auth['subkey']['keyvalue']).hex())
                if auth['seq-number'].hasValue():
                    print(f"{GREEN}[+] Sequence number:{RESET}", int(auth['seq-number']))
            except Exception as e:
                print("[*] Could not parse Authenticator:", e)
        return

    # AP-REP
    if args.mode == "ap-rep":
        encpart_cipher_hex = args.encpart_cipher
        encpart_etype = args.encpart_etype
        
        if not encpart_cipher_hex:
            print("[!] Provide --encpart-cipher for AP-REP decryption."); sys.exit(1)
        
        if not args.session_key:
            print("[!] --session-key (from TGS-REP) is required to decrypt AP-REP enc-part"); sys.exit(1)
        
        pt_ap = decrypt(encpart_etype, args.session_key, 12, encpart_cipher_hex)
        print("")
        print(f"{MAGENTA}[+] AP-REP enc-part decrypted hex:{RESET} {pt_ap.hex()}")
        
        try:
          
            from impacket.krb5.asn1 import EncAPRepPart
            enc_ap_rep, _ = der_decode(pt_ap, asn1Spec=EncAPRepPart())
            
       
            print(f"{GREEN}[+] AP-REP ctime:{RESET}", dt_str(str(enc_ap_rep['ctime'])))
            
            if enc_ap_rep['cusec'].hasValue():
                print(f"{GREEN}[+] AP-REP cusec:{RESET}", int(enc_ap_rep['cusec']), "microseconds")
            
            if enc_ap_rep['subkey'].hasValue():
                subkey_etype = int(enc_ap_rep['subkey']['keytype'])
                subkey_value = bytes(enc_ap_rep['subkey']['keyvalue']).hex()
                print(f"{YELLOW}[+] AP-REP subkey etype:{RESET}", subkey_etype)
                print(f"{YELLOW}[+] AP-REP subkey:{RESET}", subkey_value)
            else:
                print(f"{YELLOW}[+] AP-REP subkey:{RESET} Not present (using service session key)")
                
            if enc_ap_rep['seq-number'].hasValue():
                print(f"{YELLOW}[+] AP-REP seq-number:{RESET}", int(enc_ap_rep['seq-number']))
            else:
                print(f"{YELLOW}[+] AP-REP seq-number:{RESET} Not present")
                
        except Exception as e:
            print("[*] Could not parse EncAPRepPart:", e)
            print("[*] Raw decrypted data might be valid but structure unknown")
        return


if __name__ == "__main__":
    main()
           
