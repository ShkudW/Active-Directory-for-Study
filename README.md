# KerbFlow

A simple tool for understanding Kerberos network flow
I wrote the tool to gain a deeper understanding of how Kerberos works.


```python
 .\python.exe .\kerbflow.py -h
usage: KerbFlow.py [-h] {as-req,as-rep,tgs-req,tgs-rep,ap-req,ap-rep,krb-cred} ...

Kerberos helper

positional arguments:
  {as-req,as-rep,tgs-req,tgs-rep,ap-req,ap-rep,krb-cred}
    as-req              AS-REQ : Authentication Request packet ( Client -> KDC )
    as-rep              AS-REP : Authentication Reply packet ( KDC-> Client )
    tgs-req             TGS-REQ : Ticket Granting Serivce Request packet ( Client -> KDC )
    tgs-rep             TGS-REP : Ticket Granting Serivce Reply packet ( KDC -> Client )
    ap-req              AP_REQ: Application Request packet ( Client -> Application Service )
    ap-rep              AP_RP: Application Reply packet ( Application Service -> Client )
    krb-cred            KRB-CRED EncKrbCredPart decryption

options:
  -h, --help            show this help message and exit
```

You are more than welcome to read the article I wrote :)
https://medium.com/@shakedwe2/deconstructing-kerberos-authentication-on-windows-6f9c1aa469e2
