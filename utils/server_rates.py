from enum import Enum


class GradesEnum(Enum):
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

    ** Implementation is is ResultsParser class **
    """

    PROTOCOL_FACTOR = 0.3
    KEY_FACTOR = 0.3
    CIPHER_FACTOR = 0.4
    A_PLUS = 1   # good configuration, no warnings.
    A_MINUS = 2  # good configuration that have one or more warnings.
    B = 3        # TODO: description
    C = 4        # TODO: description
    D = 5        # TODO: description
    E = 6        # TODO: description
    F = 7        # TODO: description
    T = 8        # site certificate is not trusted


class ProtocolScoreEnum(Enum):
    """
    1) Protocol support:
        SSL 2.0:	0       **V**
        SSL 3.0:	80      **V**
        TLS 1.0:	90      **V**
        TLS 1.1:	95      **V**
        TLS 1.2:	100     **V**

        Total score: best protocol score + worst protocol score, divided by 2.
    """
    SSLv20 = 0
    SSLv30 = 80
    TLSv10 = 90
    TLSv11 = 95
    TLSv12 = 100


class KeyExchangeScoreEnum(Enum):
    """
    2) Key exchange:
        Weak key (Debian OpenSSL flaw): 	                         0
        Anonymous key exchange (no authentication)	                 0
        Key or DH parameter strength < 512 bits	                     20     **V**
        Exportable key exchange (limited to 512 bits)	             40
        Key or DH parameter strength < 1024 bits (e.g., 512)	     40     **V**
        Key or DH parameter strength < 2048 bits (e.g., 1024)	     80     **V**
        Key or DH parameter strength < 4096 bits (e.g., 2048)	     90     **V**
        Key or DH parameter strength >= 4096 bits (e.g., 4096)	     100    **V**
    """
    LessThan512 = 20
    LessThan1024 = 40
    LessThan2048 = 80
    LessThan4096 = 90
    EqualOrGreaterThan4096 = 100


class CipherStrengthScoreEnum(Enum):
    """
    3) Cipher strength:
        0 bits (no encryption)	        0
        < 128 bits (e.g., 40, 56)	    20
        < 256 bits (e.g., 128, 168)	    80
        >= 256 bits (e.g., 256)	        100

        Total score: strongest cipher score + weakest cipher score, divided by 2.
    """
    NoEncryption = 0
    LessThan128 = 20
    LessThan256 = 80
    EqualOrGraterThan256 = 100


"""
4) Mandatory rates:
   - **V** SSL 2.0 is not allowed (F). **V**
   - **V** If vulnerable to the Heartbleed attack, it will be given F. **V**
   - **V** If vulnerable to the OpenSSL CVE-2014-0224 vulnerability, it will be given F. **V**
   - **V** Servers that use SHA1 certificates can't get an A+. **V**
   - **V** Cap to C if vulnerable to POODLE. **V**
   - **V** Don’t award A+ to servers that don’t support TLS_FALLBACK_SCSV. **V** 
   - **V** Vulnerability to DROWN: servers get an F. **V**
   - **V** Insecure renegotiation is not allowed (F). **V**
   - Vulnerability to the BEAST attack caps the grade at B.
   - Vulnerability to the CRIME attack caps the grade at B.
   - Support for TLS 1.2 is now required to get the A grade. Without, the grade is capped a B.
   - Keys below 2048 bits (e.g., 1024) are now considered weak, and the grade capped at B.
   - Keys under 1024 bits are now considered insecure (F).
   - MD5 certificate signatures is not allowed (F).
   - Cap to B if SSL 3 is supported.
   - (F) if server's best protocol is SSL 3.0
   - Cap to C if not supporting TLS 1.2.
   - If vulnerable to CVE-2016-2107 (Padding oracle in AES-NI CBC MAC check) it will be given F.
   - SHA1 certificates are now longer trusted (T).
   - If vulnerable to the Ticketbleed (CVE-2016-9244), it will be given F.
   - WoSign/StartCom certificates distrusted, will get 'T' grade.
    
"""

"""
For these reasons, any of the following certificate issues immediately result in a zero score:

Domain name mismatch                                                                    **V**
Certificate not yet valid                                                               **V**
Certificate expired                                                                     **V**
Use of a self-signed certificate
Use of a certificate that is not trusted (unknown CA or some other validation error)    **V**
Use of a revoked certificate
Insecure certificate signature (MD2 or MD5)
Insecure key

"""