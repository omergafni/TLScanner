from enum import Enum


class Grades(Enum):
    """
    Letter grade translation:
    A - if score >= 80
    B - if score >= 65
    C - if score >= 50
    D - if score >= 35
    E - if score >= 20
    F - if score < 20

    Total grade will be a combination of:
    1) Protocol support (30%)
    2) Key exchange (30%)
    3) Cipher strength (40%)
    """
    A_PLUS = 1   # good configuration, no warnings.
    A_MINUS = 2  # good configuration that have one or more warnings.
    B = 3
    C = 4
    D = 5
    E = 6
    F = 7
    T = 8        # site certificate is not trusted
"""
1) Protocol support:
    SSL 2.0:	0
    SSL 3.0:	80
    TLS 1.0:	90
    TLS 1.1:	95
    TLS 1.2:	100

    Total score: best protocol score + worst protocol score, divided by 2.
    
2) Key exchange:
    Weak key (Debian OpenSSL flaw): 	                         0
    Anonymous key exchange (no authentication)	                 0
    Key or DH parameter strength < 512 bits	                     20
    Exportable key exchange (limited to 512 bits)	             40
    Key or DH parameter strength < 1024 bits (e.g., 512)	     40
    Key or DH parameter strength < 2048 bits (e.g., 1024)	     80
    Key or DH parameter strength < 4096 bits (e.g., 2048)	     90
    Key or DH parameter strength >= 4096 bits (e.g., 4096)	     100

3) Cipher strength:
    0 bits (no encryption)	        0
    < 128 bits (e.g., 40, 56)	    20
    < 256 bits (e.g., 128, 168)	    80
    >= 256 bits (e.g., 256)	        100
    
    Total score: strongest cipher score + weakest cipher score, divided by 2.
"""

"""
4) Mandatory rates:
   a) SSL 2.0 is not allowed (F).
   b) Insecure renegotiation is not allowed (F).
   c) Vulnerability to the BEAST attack caps the grade at B.
   d) Vulnerability to the CRIME attack caps the grade at B.
   e) Support for TLS 1.2 is now required to get the A grade. Without, the grade is capped a B.
   f) If vulnerable to the Heartbleed attack, it will be given F.
   g) If vulnerable to the OpenSSL CVE-2014-0224 vulnerability, it will be given F.
   h) Keys below 2048 bits (e.g., 1024) are now considered weak, and the grade capped at B.
   i) Keys under 1024 bits are now considered insecure (F).
   j) MD5 certificate signatures is not allowed (F).
   k) Servers that use SHA1 certificates can't get an A+.
   l) Cap to C if vulnerable to POODLE.
   m) Don’t award A+ to servers that don’t support TLS_FALLBACK_SCSV.
   n) Cap to B if SSL 3 is supported.
   o) (F) if server's best protocol is SSL 3.0
   p) Cap to C if not supporting TLS 1.2.
   q) Vulnerability to DROWN: servers get an F.
   r) If vulnerable to CVE-2016-2107 (Padding oracle in AES-NI CBC MAC check) it will be given F.
   s) SHA1 certificates are now longer trusted (T).
   t) If vulnerable to the Ticketbleed (CVE-2016-9244), it will be given F.
   u) WoSign/StartCom certificates distrusted, will get 'T' grade.
    
"""
