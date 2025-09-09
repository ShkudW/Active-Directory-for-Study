from binascii import unhexlify
from pyasn1.codec.der.decoder import decode as der_decode
from impacket.krb5.asn1 import (AS_REQ, AS_REP, AP_REQ, TGS_REP,Authenticator,EncryptedData, PA_ENC_TS_ENC,EncASRepPart, EncTGSRepPart, EncTicketPart)
from impacket.krb5.crypto import _enctype_table, Key
from datetime import datetime
import argparse
import sys

from pyasn1.codec.der.decoder import decode as der_decode
from impacket.krb5.asn1 import EncTicketPart, AuthorizationData
try:
    from impacket.krb5.pac import KERB_VALIDATION_INFO as _VALIDATION_CLS
except Exception:
    try:
        from impacket.krb5.pac import VALIDATION_INFO as _VALIDATION_CLS
    except Exception:
        _VALIDATION_CLS = None

from struct import unpack_from
from datetime import datetime, timezone

################################################## COLORRRRRRRR

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

def flags_to_names(v: int):
    KERB_FLAGS = [(1,"forwardable"),(8,"renewable"),(9,"initial"),(10,"pre_authent"),(15,"enc_pa_rep")]
    names = [name for bit, name in KERB_FLAGS if v & (1 << bit)]
    return names or [f"0x{v:08x}"]

def read_utf16le(buf, off, ln):
    try:
        if ln and 0 <= off < len(buf) and off+ln <= len(buf):
            return buf[off:off+ln].decode('utf-16le', errors='ignore')
    except Exception:
        pass
    return None

def filetime_to_dt_str(lo, hi):
    ft = (int(hi) << 32) | int(lo)
    if ft == 0: return "-"
    unix_100ns = ft - 116444736000000000
    ts = unix_100ns / 10_000_000
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

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

def _read_us_selfrel(buf, us):
    try:
        ln = int(us['Length']); off = int(us['Buffer'])
        return read_utf16le(buf, off, ln) or ""
    except Exception:
        try: return us.string
        except Exception: return str(us)

def parse_pac_logon_info(buf_bytes: bytes):
    info = {}
    try:
        if _VALIDATION_CLS is None:
            raise RuntimeError("No VALIDATION_INFO in impacket")
        logon = _VALIDATION_CLS(); logon.fromString(buf_bytes)
        for k in ("UserId","PrimaryGroupId","GroupCount"):
            try: info[k] = int(logon[k])
            except Exception: pass
        try: info["UserName"] = _read_us_selfrel(buf_bytes, logon['UserName']) or _read_us_selfrel(buf_bytes, logon['EffectiveName'])
        except Exception: pass
        try: info["LogonDomainName"] = _read_us_selfrel(buf_bytes, logon['LogonDomainName'])
        except Exception: pass
        try:
            sid = logon['UserSid']
            info["UserSid"] = sid.formatCanonical() if hasattr(sid,"formatCanonical") else str(sid)
        except Exception: pass
    except Exception as e:
        info["_error"] = f"VALIDATION_INFO parse failed: {e}"
    return {k:v for k,v in info.items() if v not in (None,"",[])}

def parse_pac_client_info(buf: bytes):
    out = {}
    if len(buf) >= 10:
        lo, hi = unpack_from("<II", buf, 0)
        nlen = unpack_from("<H", buf, 8)[0]
        out["ClientName"] = read_utf16le(buf, 10, nlen) or ""
        out["ClientId"]   = filetime_to_dt_str(lo, hi)
    return out

def parse_pac_upn_dns_info(buf: bytes):
    out = {}
    if len(buf) >= 12:
        upn_len, upn_off, dns_len, dns_off, flags = unpack_from("<HHHHI", buf, 0)
        upn = read_utf16le(buf, upn_off, upn_len); dns = read_utf16le(buf, dns_off, dns_len)
        if upn: out["UPN"] = upn
        if dns: out["DNSDomainName"] = dns
        out["UPN_Flags"] = f"0x{flags:08x}"
    return out

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

def parse_pac_requestor(buf: bytes):
    sid = parse_sid(buf, 0); return {"UserSid": sid} if sid else {}

def parse_pac_signature(buf: bytes):
    out = {}
    if len(buf) >= 4:
        sig_type = unpack_from("<I", buf, 0)[0]
        out["SignatureType"] = f"{sig_type} (0x{sig_type:08x})"
        out["Signature"]     = buf[4:].hex()
    return out

def pretty_print_enc_ticket_part_and_pac(decrypted_enc_ticket_part_bytes: bytes):
    enc, _ = der_decode(decrypted_enc_ticket_part_bytes, asn1Spec=EncTicketPart())

    print(f"{Colors.BOLD}{Colors.MAGENTA}=== EncTicketPart ==={Colors.RESET}")
    try:
        flags_int = int(enc['flags'])
    except Exception:
        try:
            bits = list(enc['flags'].asNumbers()); v=0
            for b in bits: v = (v<<1) | (1 if b else 0)
            flags_int = v
        except Exception:
            flags_int = None

    if flags_int is not None:
        print(f"{Colors.YELLOW}Ticket Flags:{Colors.RESET} 0x{flags_int:08x} "
              f"-> {Colors.CYAN}{', '.join(flags_to_names(flags_int))}{Colors.RESET}")
    else:
        print(f"{Colors.RED}Ticket Flags: (unavailable){Colors.RESET}")

    kt = int(enc['key']['keytype']); kv = bytes(enc['key']['keyvalue']).hex()
    print(f"{Colors.YELLOW}Session Key:{Colors.RESET} etype={Colors.GREEN}{kt}{Colors.RESET} "
          f"key={Colors.CYAN}{kv}{Colors.RESET}")
    print(f"{Colors.YELLOW}Realm:{Colors.RESET} {Colors.GREEN}{str(enc['crealm'])}{Colors.RESET}")

    cname = enc['cname']; nt = None
    try: nt = int(cname['name-type'])
    except Exception: pass
    names = [str(x) for x in cname['name-string']]
    print(f"{Colors.YELLOW}Client:{Colors.RESET} type={nt}  name={Colors.CYAN}{'/'.join(names)}{Colors.RESET}")

    def _gt(field):
        return str(enc[field]) if field in enc and enc[field].hasValue() else "-"
    print(f"{Colors.YELLOW}Times:{Colors.RESET} "
          f"authtime={Colors.CYAN}{_gt('authtime')}{Colors.RESET}, "
          f"starttime={Colors.CYAN}{_gt('starttime')}{Colors.RESET}, "
          f"endtime={Colors.CYAN}{_gt('endtime')}{Colors.RESET}, "
          f"renew-till={Colors.CYAN}{_gt('renew-till')}{Colors.RESET}")

    if 'authorization-data' in enc and enc['authorization-data'].hasValue():
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}=== AuthorizationData / PAC ==={Colors.RESET}")
        for idx, entry in enumerate(enc['authorization-data']):
            ad_type = int(entry['ad-type']); ad_data = bytes(entry['ad-data'])
            print(f"{Colors.BLUE}- Entry[{idx}]{Colors.RESET} ad-type={Colors.YELLOW}{ad_type}{Colors.RESET}, "
                  f"len={Colors.CYAN}{len(ad_data)}{Colors.RESET}")
            try:
                pac_bytes = extract_pac_bytes_from_ad(ad_data)
            except Exception:
                continue

            try:
                pac = parse_pac_raw(pac_bytes)
                print(f"  PAC: cBuffers={Colors.GREEN}{pac['cBuffers']}{Colors.RESET}, "
                      f"Version={Colors.GREEN}{pac['version']}{Colors.RESET}")
                for e in pac['entries']:
                    t = e['type']
                    print(f"    Buffer {e['index']}: type={Colors.YELLOW}{t}{Colors.RESET}, "
                          f"size={Colors.CYAN}{e['size']}{Colors.RESET}, offset={e['offset']}")
                    try:
                        if   t == 1:  info = parse_pac_logon_info(e['data'])
                        elif t == 10: info = parse_pac_client_info(e['data'])
                        elif t == 12: info = parse_pac_upn_dns_info(e['data'])
                        elif t == 17: info = {"Attributes": parse_pac_attributes_info(e['data']).get("Flags","")}
                        elif t == 18: info = parse_pac_requestor(e['data'])
                        elif t in (6,7): info = parse_pac_signature(e['data'])
                        else: info = None
                        if info:
                            for k,v in info.items():
                                print(f"      {Colors.GREEN}{k}{Colors.RESET}: {Colors.CYAN}{v}{Colors.RESET}")
                    except Exception as ex:
                        print(f"      {Colors.RED}[parse error type={t}]: {ex}{Colors.RESET}")
            except Exception as e:
                print(f"  {Colors.RED}[!] PAC parse failed: {e}{Colors.RESET}")
    else:
        print(f"\n{Colors.YELLOW}(No authorization-data present){Colors.RESET}")



#########################################################################################################################
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
        return datetime.strptime(pat, "%Y%m%d%H%M%SZ").isoformat() + "Z"
    except Exception:
        return pat

##################################################################################
def decrypt(etype: int, key_hex: str, usage: int, cipher_hex: str) -> bytes:
    key = Key(etype, unhexlify(key_hex))
    crypto = _enctype_table[etype]
    return crypto.decrypt(key, usage, unhexlify(cipher_hex))

##################################################################################

def parse_args():
    p = argparse.ArgumentParser(prog="Kerberos.py", description="Kerberos helper")
    sub = p.add_subparsers(dest="mode", required=True)

    # AS-REQ 
    asreq = sub.add_parser("as-req", help="AS-REQ    : Decrypt PA-ENC-TIMESTAMP using rc4_hmac or aes256 hash client")
    src = asreq.add_mutually_exclusive_group(required=True)
    src.add_argument("--padata-value", help="HEX Stream value of padata-value in 'PA-DATA pA-ENC-TIMESTAMP'")
    src.add_argument("--cipher", help="HEX Stream value of cipher in 'PA-DATA pA-ENC-TIMESTAMP'")
    asreq.add_argument("--key", required=True, help="rc4_hmac or aes256 hash client")
    asreq.add_argument("--etype", type=int, help="Key etype use '2' for pdata-vaule, or '23' for cipher")

    # AS-REP 
    asrep = sub.add_parser("as-rep", help="AS-REP    : Decrypt TGT (Service Ticket) using aes256_cts_hmac_sha1 hash krbtgt service account, and decrypt Client-Enc-Part using rc4_hmac hash client")
    tg = asrep.add_argument_group("TGT enc-part")
    tg_src = tg.add_mutually_exclusive_group()
    tg_src.add_argument("--tgt-ticket", help="HEX Stream value cipher of TGT enc-part")
    tg.add_argument("--krbtgt-key", help="es256_cts_hmac_sha1 hash krbtgt service account")
    tg.add_argument("--ticket-etype", type=int, default=18, help="Key etype for cipher TGT-enc-part Default 18, use: (17/18/23)")

    cl = asrep.add_argument_group("Client enc-part")
    cl_src = cl.add_mutually_exclusive_group()
    cl_src.add_argument("--client-cipher", help="HEX Stream cipher of client enc-part")
    cl.add_argument("--client-key", help="client key (rc4/aes256)")
    cl.add_argument("--client-etype", type=int, default=23, help="Key etype for cipher Client-enc-part Default 23, use: (17/18/23)")

    # TGS-REQ
    tgs = sub.add_parser("tgs-req", help="TGS-REQ   :  Decrypt TGT (Service Ticket) using aes256_cts_hmac_sha1 hash krbtgt service account, and decrypt authenticator part using session key from AS-REP")
    tg = tgs.add_argument_group("TGT enc-part")
    tgs_src_tkt = tgs.add_mutually_exclusive_group()
    tgs_src_tkt.add_argument("--tgt-ticket", help="HEX Stream cipher of TGT enc-part (from AS-REP)")
    tgs.add_argument("--tgt-ticket-key", help="krbtgt key for decrypting TGT enc-part")
    tgs.add_argument("--tgt-ticket-etype", type=int, default=18, help="Key etype cipher for TGT-enc-part Default 18, use: (17/18/23)")

    tg_auth = tgs.add_argument_group("Authenticator enc-part")
    tgs_src_auth = tgs.add_mutually_exclusive_group()
    tgs_src_auth.add_argument("--authenticator-cipher", help="HEX cipher of AP-REQ authenticator")
    tgs.add_argument("--session-key", help="AS-REP session key (to decrypt authenticator)")
    tgs.add_argument("--authenticator-etype", type=int, default=23, help="Key etype cipher for Authenticator enc-part Default 23, use: (17/18/23)")

    # TGS-REP
    tgsrep = sub.add_parser("tgs-rep", help="TGS-REP    : Decrypt TGS (Service-Ticket) using rc4_hmac hash service acocunt, and decrypt Client-Enc-Part sing session key from AS-REP")
    grp_t = tgsrep.add_argument_group("TGS enc-part (ticket)")
    grp_t_src = grp_t.add_mutually_exclusive_group()
    grp_t_src.add_argument("--tgs-ticket", help="HEX cipher of service ticket enc-part")
    grp_t.add_argument("--tgs-service-key", help="service account key (rc4/aes)")
    grp_t.add_argument("--tgs-ticket-etype", type=int, default=23, help="Key etype cipher for TGS-enc-part Default 23, use: (17/18/23)")

    grp_c = tgsrep.add_argument_group("Client enc-part (EncTGSRepPart)")
    grp_c_src = grp_c.add_mutually_exclusive_group()
    grp_c_src.add_argument("--encpart-cipher", help="HEX cipher of EncTGSRepPart")
    grp_c.add_argument("--session-key", help="reply key (AS-REP session key or subkey)")
    grp_c.add_argument("--encpart-etype", type=int, default=23, help="Key etype cipher for client enc-part Default 23, use: (17/18/23)")

    return p.parse_args()

##################################################################################

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
            pretty_print_enc_ticket_part_and_pac(pt_t)
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


if __name__ == "__main__":
    main()
           
