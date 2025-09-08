from binascii import unhexlify
from pyasn1.codec.der.decoder import decode as der_decode
from impacket.krb5.asn1 import AP_REQ, AS_REP, Authenticator, EncASRepPart, EncTicketPart
from impacket.krb5.crypto import _enctype_table, Key
import argparse

def is_ap_req(b: bytes) -> bool:  # APPLICATION 14
    return len(b) > 0 and b[0] == 0x6e

def is_as_rep(b: bytes) -> bool:  # APPLICATION 11
    return len(b) > 0 and b[0] == 0x6b

def main():
    p = argparse.ArgumentParser(description="Kerberos blob decryptor")
    p.add_argument("--blob-type", choices=["auth","tgsrep","ticket","asrep"], required=True, help="auth=Authenticator(AP-REQ/TGS-REQ, usage=7), tgsrep=TGS-REP enc-part (usage=8), ticket=AS-REP ticket.enc-part (usage=2), asrep=AS-REP client enc-part (usage=3)")
    p.add_argument("--key", required=True, help="Hex key: Session key (auth/tgsrep) / krbtgt key (ticket) / user key (asrep)")
    p.add_argument("--etype", type=int, help="Key etype (23=rc4, 18=aes256, 17=aes128). If omitted and input is full structure, will try to auto-detect.")
    p.add_argument("--data", required=True, help="Hex of the encrypted blob. For auth: authenticator.cipher or whole AP-REQ; for ticket/asrep: the respective enc-part.cipher.")
    args = p.parse_args()

    key_bytes = unhexlify(args.key)
    blob = unhexlify(args.data)

    usage_map = {"auth":7, "tgsrep":8, "ticket":2, "asrep":3}
    usage = usage_map[args.blob_type]

    etype = args.etype
    cipher = blob

    if args.blob_type == "auth":
        if is_ap_req(blob):
            apreq, _ = der_decode(blob, asn1Spec=AP_REQ())
            enc_auth = apreq['authenticator']
            etype = int(enc_auth['etype']) if etype is None else etype
            cipher = bytes(enc_auth['cipher'])
        else:
            if etype is None:
                etype = 23 
    elif args.blob_type == "ticket":
        if etype is None:
            etype = 18  
    elif args.blob_type == "asrep":
       
        if is_as_rep(blob):
            asrep, _ = der_decode(blob, asn1Spec=AS_REP())
            enc = asrep['enc-part']
            etype = int(enc['etype']) if etype is None else etype
            cipher = bytes(enc['cipher'])
        else:
            if etype is None:
                etype = 23 
    elif args.blob_type == "tgsrep":
        if etype is None:
            etype = 23 

    key = Key(etype, key_bytes)
    crypto = _enctype_table[etype]

    plaintext = crypto.decrypt(key, usage, cipher)
    print(f"[+] Decrypted (usage={usage}) hex:", plaintext.hex())

    try:
        if args.blob_type == "auth":
            auth, _ = der_decode(plaintext, asn1Spec=Authenticator())
            print("[+] Authenticator cname:", str(auth['cname']))
            print("[+] Authenticator crealm:", str(auth['crealm']))
            print("[+] Authenticator ctime:", str(auth['ctime']), "usec:", int(auth['cusec']))
          
        elif args.blob_type == "asrep":
            encp, _ = der_decode(plaintext, asn1Spec=EncASRepPart())
            print("[+] AS-REP session key etype:", int(encp['key']['keytype']))
            print("[+] AS-REP session key (hex):", bytes(encp['key']['keyvalue']).hex())
          
        elif args.blob_type == "ticket":
            enc_tkt, _ = der_decode(plaintext, asn1Spec=EncTicketPart())
            print("[+] EncTicketPart key etype:", int(enc_tkt['key']['keytype']))
            print("[+] EncTicketPart session key (hex):", bytes(enc_tkt['key']['keyvalue']).hex())
          
    except Exception as e:
        print("[*] Decrypted but could not parse ASN.1 for this blob-type:", e)

if __name__ == "__main__":
    main()
