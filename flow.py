#!/usr/bin/env python3
from binascii import unhexlify
from pyasn1.codec.der.decoder import decode as der_decode
from impacket.krb5.asn1 import (
    AS_REQ, AS_REP, AP_REQ, Authenticator,
    EncryptedData, PA_ENC_TS_ENC,
    EncASRepPart, EncTicketPart
)
from impacket.krb5.crypto import _enctype_table, Key
from datetime import datetime
import argparse
import sys

def dt_str(pat: str) -> str:
    try:
        return datetime.strptime(pat, "%Y%m%d%H%M%SZ").isoformat() + "Z"
    except Exception:
        return pat

def decrypt(etype: int, key_hex: str, usage: int, cipher_hex: str) -> bytes:
    key = Key(etype, unhexlify(key_hex))
    crypto = _enctype_table[etype]
    return crypto.decrypt(key, usage, unhexlify(cipher_hex))

def parse_args():
    p = argparse.ArgumentParser(prog="tool.py", description="Kerberos helper")
    sub = p.add_subparsers(dest="mode", required=True)

    # --- Mode 1: AS-REQ / PA-ENC-TIMESTAMP ---
    asreq = sub.add_parser(
        "as-req",
        help="Decrypt PA-ENC-TIMESTAMP from AS-REQ using user key (NT hash for RC4 or S2K for AES)."
    )
    src = asreq.add_mutually_exclusive_group(required=True)
    src.add_argument("--padata-value",
                     help="HEX of padata-value (DER-encoded EncryptedData of PA-ENC-TIMESTAMP).")
    src.add_argument("--cipher",
                     help="HEX of inner EncryptedData.cipher (the raw ciphertext bytes).")
    asreq.add_argument("--key", required=True,
                       help="User key in HEX (e.g., NT hash for RC4 / S2K for AES).")
    asreq.add_argument("--etype", type=int,
                       help="Key etype: 23=RC4-HMAC, 18=AES256, 17=AES128. "
                            "Required with --cipher; optional with --padata-value (auto-detect).")

    # --- Mode 2: AS-REP (ticket.enc-part and/or client enc-part) ---
    asrep = sub.add_parser(
        "as-rep",
        help="Decrypt AS-REP parts (ticket.enc-part with krbtgt key, client enc-part with user key)."
    )
    asrep.add_argument("--as-rep-full",
                       help="HEX of full AS-REP (auto-extract both EncryptedData blocks).")

    # ticket.enc-part (krbtgt key, usage=2)
    tg = asrep.add_argument_group("ticket.enc-part (krbtgt key, usage=2)")
    tg_src = tg.add_mutually_exclusive_group()
    tg_src.add_argument("--ticket-ed", help="HEX of DER EncryptedData (ticket.enc-part)")
    tg_src.add_argument("--ticket-cipher", help="HEX of inner cipher (ticket.enc-part.cipher)")
    tg.add_argument("--krbtgt-key", help="krbtgt key HEX (matches --ticket-etype)")
    tg.add_argument("--ticket-etype", type=int,
                    help="etype for krbtgt key (e.g., 18). Required if using --ticket-cipher.")

    # client enc-part (user key, usage=3)
    cl = asrep.add_argument_group("client enc-part (user key, usage=3)")
    cl_src = cl.add_mutually_exclusive_group()
    cl_src.add_argument("--encpart-ed", help="HEX of DER EncryptedData (AS-REP enc-part)")
    cl_src.add_argument("--encpart-cipher", help="HEX of inner cipher (AS-REP enc-part.cipher)")
    cl.add_argument("--user-key", help="User key HEX (NT hash / AES S2K)")
    cl.add_argument("--encpart-etype", type=int,
                    help="etype for user key (23/17/18). Required if using --encpart-cipher.")

    # --- Mode 3: TGS-REQ (PA-TGS-REQ = AP-REQ) ---
    tgs = sub.add_parser(
        "tgs-req",
        help="Parse PA-TGS-REQ (AP-REQ) and decrypt ticket/authenticator; optional: enc-authorization-data."
    )
    tgs.add_argument("--pa-tgs-req",
                     help="HEX of padata-value for PA-TGS-REQ (DER AP-REQ).")

    # parts explicitly (if not using --pa-tgs-req)
    tgs_src_tkt = tgs.add_mutually_exclusive_group()
    tgs_src_tkt.add_argument("--ticket-ed", help="HEX of DER EncryptedData for AP-REQ ticket.enc-part")
    tgs_src_tkt.add_argument("--ticket-cipher", help="HEX of inner cipher for AP-REQ ticket.enc-part")

    tgs_src_auth = tgs.add_mutually_exclusive_group()
    tgs_src_auth.add_argument("--auth-ed", help="HEX of DER EncryptedData for AP-REQ authenticator")
    tgs_src_auth.add_argument("--auth-cipher", help="HEX of inner cipher for AP-REQ authenticator")

    tgs.add_argument("--krbtgt-key", help="krbtgt key HEX (to decrypt ticket.enc-part and derive TGS session key)")
    tgs.add_argument("--ticket-etype", type=int, help="etype for krbtgt key (e.g., 18) with --ticket-cipher")
    tgs.add_argument("--session-key", help="Known TGS session key HEX (skip ticket decryption)")
    tgs.add_argument("--auth-etype", type=int, help="etype for authenticator with --auth-cipher")

    # optional: enc-authorization-data from req-body
    tgs_src_authz = tgs.add_mutually_exclusive_group()
    tgs_src_authz.add_argument("--authz-ed", help="HEX of DER EncryptedData for enc-authorization-data")
    tgs_src_authz.add_argument("--authz-cipher", help="HEX of inner cipher for enc-authorization-data")

    return p.parse_args()

def main():
    args = parse_args()

    # ===== AS-REQ =====
    if args.mode == "as-req":
        if args.padata_value:
            ed, _ = der_decode(unhexlify(args.padata_value), asn1Spec=EncryptedData())
            etype = int(ed['etype']) if args.etype is None else args.etype
            cipher_hex = bytes(ed['cipher']).hex()
        else:
            if args.etype is None:
                print("[!] --etype is required when using --cipher.", file=sys.stderr)
                sys.exit(1)
            etype = args.etype
            cipher_hex = args.cipher

        pt = decrypt(etype, args.key, 1, cipher_hex)  # usage=1
        print(f"[+] Decrypted (usage=1) hex: {pt.hex()}")
        try:
            ts, _ = der_decode(pt, asn1Spec=PA_ENC_TS_ENC())
            print("[+] patimestamp:", dt_str(str(ts['patimestamp'])))
            print("    usec:", int(ts['pausec']) if ts['pausec'].hasValue() else "<absent>")
        except Exception as e:
            print("[*] Decrypted but could not parse PA-ENC-TS-ENC:", e)
            sys.exit(2)
        return

    # ===== AS-REP =====
    if args.mode == "as-rep":
        ticket_cipher_hex = None
        ticket_etype = args.ticket_etype
        encpart_cipher_hex = None
        encpart_etype = args.encpart_etype

        if args.as_rep_full:
            asrep, _ = der_decode(unhexlify(args.as_rep_full), asn1Spec=AS_REP())
            ed_t = asrep['ticket']['enc-part']
            if ticket_etype is None:
                ticket_etype = int(ed_t['etype'])
            ticket_cipher_hex = bytes(ed_t['cipher']).hex()

            ed_c = asrep['enc-part']
            if encpart_etype is None:
                encpart_etype = int(ed_c['etype'])
            encpart_cipher_hex = bytes(ed_c['cipher']).hex()

        if args.ticket_ed:
            ed_t, _ = der_decode(unhexlify(args.ticket_ed), asn1Spec=EncryptedData())
            if ticket_etype is None:
                ticket_etype = int(ed_t['etype'])
            ticket_cipher_hex = bytes(ed_t['cipher']).hex()
        elif args.ticket_cipher:
            ticket_cipher_hex = args.ticket_cipher
            if ticket_etype is None:
                print("[!] --ticket-etype is required with --ticket-cipher", file=sys.stderr)
                sys.exit(1)

        if args.encpart_ed:
            ed_c, _ = der_decode(unhexlify(args.encpart_ed), asn1Spec=EncryptedData())
            if encpart_etype is None:
                encpart_etype = int(ed_c['etype'])
            encpart_cipher_hex = bytes(ed_c['cipher']).hex()
        elif args.encpart_cipher:
            encpart_cipher_hex = args.encpart_cipher
            if encpart_etype is None:
                print("[!] --encpart-etype is required with --encpart-cipher", file=sys.stderr)
                sys.exit(1)

        if not any([ticket_cipher_hex, encpart_cipher_hex]):
            print("[!] Provide --as-rep-full or at least one of ticket/enc-part inputs.", file=sys.stderr)
            sys.exit(1)

        if ticket_cipher_hex:
            if not args.krbtgt_key:
                print("[!] --krbtgt-key is required to decrypt ticket.enc-part", file=sys.stderr)
                sys.exit(1)
            pt_t = decrypt(ticket_etype, args.krbtgt_key, 2, ticket_cipher_hex)  # usage=2
            print(f"[+] ticket.enc-part decrypted (usage=2) hex: {pt_t.hex()}")
            try:
                enc_tkt, _ = der_decode(pt_t, asn1Spec=EncTicketPart())
                kt = int(enc_tkt['key']['keytype'])
                kv = bytes(enc_tkt['key']['keyvalue']).hex()
                print(f"[+] EncTicketPart key etype: {kt}")
                print(f"[+] EncTicketPart session key: {kv}")
            except Exception as e:
                print("[*] Could not parse EncTicketPart:", e)

        if encpart_cipher_hex:
            if not args.user_key:
                print("[!] --user-key is required to decrypt client enc-part", file=sys.stderr)
                sys.exit(1)
            pt_c = decrypt(encpart_etype, args.user_key, 3, encpart_cipher_hex)  # usage=3
            print(f"[+] client enc-part decrypted (usage=3) hex: {pt_c.hex()}")
            try:
                encp, _ = der_decode(pt_c, asn1Spec=EncASRepPart())
                kt = int(encp['key']['keytype'])
                kv = bytes(encp['key']['keyvalue']).hex()
                print(f"[+] AS-REP session key etype: {kt}")
                print(f"[+] AS-REP session key: {kv}")
                if encp['authtime'].hasValue():
                    print("[+] authtime:", dt_str(str(encp['authtime'])))
                if encp['starttime'].hasValue():
                    print("[+] starttime:", dt_str(str(encp['starttime'])))
                if encp['endtime'].hasValue():
                    print("[+] endtime:", dt_str(str(encp['endtime'])))
                if encp['renew-till'].hasValue():
                    print("[+] renew-till:", dt_str(str(encp['renew-till'])))
            except Exception as e:
                print("[*] Could not parse EncASRepPart:", e)
        return

    # ===== TGS-REQ (PA-TGS-REQ = AP-REQ) =====
    if args.mode == "tgs-req":
        ticket_cipher_hex = None; ticket_etype = args.ticket_etype
        auth_cipher_hex   = None; auth_etype   = args.auth_etype

        # If got the whole PA-TGS-REQ (AP-REQ)
        if args.pa_tgs_req:
            apreq, _ = der_decode(unhexlify(args.pa_tgs_req), asn1Spec=AP_REQ())
            t_ed = apreq['ticket']['enc-part']
            if ticket_etype is None: ticket_etype = int(t_ed['etype'])
            ticket_cipher_hex = bytes(t_ed['cipher']).hex()
            a_ed = apreq['authenticator']
            if auth_etype is None: auth_etype = int(a_ed['etype'])
            auth_cipher_hex = bytes(a_ed['cipher']).hex()

        if args.ticket_ed:
            ed, _ = der_decode(unhexlify(args.ticket_ed), asn1Spec=EncryptedData())
            if ticket_etype is None: ticket_etype = int(ed['etype'])
            ticket_cipher_hex = bytes(ed['cipher']).hex()
        elif args.ticket_cipher:
            ticket_cipher_hex = args.ticket_cipher
            if ticket_etype is None:
                print("[!] --ticket-etype is required with --ticket-cipher", file=sys.stderr)
                sys.exit(1)

        if args.auth_ed:
            ed, _ = der_decode(unhexlify(args.auth_ed), asn1Spec=EncryptedData())
            if auth_etype is None: auth_etype = int(ed['etype'])
            auth_cipher_hex = bytes(ed['cipher']).hex()
        elif args.auth_cipher:
            auth_cipher_hex = args.auth_cipher
            if auth_etype is None:
                print("[!] --auth-etype is required with --auth-cipher", file=sys.stderr)
                sys.exit(1)

        if not any([ticket_cipher_hex, auth_cipher_hex]):
            print("[!] Provide --pa-tgs-req or ticket/authenticator inputs.", file=sys.stderr)
            sys.exit(1)

        # Get TGS session key (either provided or by decrypting ticket.enc-part)
        tgs_sess_key = args.session_key
        if tgs_sess_key is None:
            if not (ticket_cipher_hex and args.krbtgt_key):
                print("[!] Need --session-key OR (--ticket + --krbtgt-key) to obtain TGS session key.", file=sys.stderr)
                sys.exit(1)
            pt_t = decrypt(ticket_etype, args.krbtgt_key, 2, ticket_cipher_hex)  # usage=2
            print(f"[+] ticket.enc-part decrypted (usage=2) hex: {pt_t.hex()}")
            try:
                enc_tkt, _ = der_decode(pt_t, asn1Spec=EncTicketPart())
                kt = int(enc_tkt['key']['keytype'])
                kv = bytes(enc_tkt['key']['keyvalue']).hex()
                print(f"[+] TGS session key etype: {kt}")
                print(f"[+] TGS session key: {kv}")
                tgs_sess_key = kv
            except Exception as e:
                print("[*] Could not parse EncTicketPart to get session key:", e)
                sys.exit(2)

        # Decrypt authenticator (usage=7)
        has_subkey = False
        if auth_cipher_hex:
            pt_a = decrypt(auth_etype, tgs_sess_key, 7, auth_cipher_hex)  # usage=7
            print(f"[+] AP-REQ authenticator decrypted (usage=7) hex: {pt_a.hex()}")
            try:
                auth, _ = der_decode(pt_a, asn1Spec=Authenticator())
                print("[+] Authenticator cname:", str(auth['cname']))
                print("[+] Authenticator crealm:", str(auth['crealm']))
                print("[+] Authenticator ctime:", dt_str(str(auth['ctime'])),
                      "usec:", int(auth['cusec']) if auth['cusec'].hasValue() else "<absent>")
                has_subkey = auth['subkey'].hasValue()
                if has_subkey:
                    subkey = bytes(auth['subkey']['keyvalue']).hex()
                    print("[+] Authenticator subkey etype:", int(auth['subkey']['keytype']))
                    print("[+] Authenticator subkey:", subkey)
            except Exception as e:
                print("[*] Could not parse Authenticator:", e)

        # Optional: enc-authorization-data (usage=4 with session key, or 5 with subkey)
        if args.authz_ed or args.authz_cipher:
            if args.authz_ed:
                ed, _ = der_decode(unhexlify(args.authz_ed), asn1Spec=EncryptedData())
                authz_etype = int(ed['etype'])
                authz_cipher_hex = bytes(ed['cipher']).hex()
            else:
                if auth_etype is None:
                    print("[!] Provide --auth-etype for --authz-cipher", file=sys.stderr); sys.exit(1)
                authz_etype = auth_etype
                authz_cipher_hex = args.authz_cipher

            usage = 5 if has_subkey else 4
            key_hex = subkey if has_subkey else tgs_sess_key
            print(f"[+] Decrypting enc-authorization-data with usage={usage} ({'subkey' if has_subkey else 'session key'})")
            pt_z = decrypt(authz_etype, key_hex, usage, authz_cipher_hex)
            print(f"[+] enc-authorization-data decrypted (usage={usage}) hex: {pt_z.hex()}")
        return

if __name__ == "__main__":
    main()
