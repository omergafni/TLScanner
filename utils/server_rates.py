from enum import Enum


class GradesEnum(Enum):
    """
    Letter grade translation:
    A - if score >= 80
    B - if score >= 65
    C - if score >= 50
    D - if score >= 35
    E - if score >= 20
    F - if score <  20

    Total grade will be a combination of:
    1) Protocol support
    2) Key exchange
    3) Cipher strength

    ** Implementation is in ResultsParser class **
    """

    PROTOCOL_FACTOR = 0.4
    KEY_FACTOR = 0.3
    CIPHER_FACTOR = 0.3

    A_PLUS = "A+ >> good configuration, no warnings."
    A_MINUS = "A- >> good configuration that have one or more warnings."
    B = "B >> "  # +parser's message
    C = "C >> "  # +parser's message
    E = "E >> "  # +parser's message
    D = "D >> "  # +parser's message
    F = "F >> "  # +parser's message
    T = "T >> site certificate is not trusted."


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
    # SSLv20 = 0 - resulting mandatory F final grade
    SSLv30 = 80
    TLSv10 = 90
    TLSv11 = 95
    TLSv12 = 100


class KeyExchangeScoreEnum(Enum):
    """
    Key exchange:
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


class CipherScoresEnum(Enum):
    """
    Cipher strength:
        0 bits (no encryption)            0
        < 128 bits (e.g., 40, 56)	     20
        < 256 bits (e.g., 128, 168)      80
        >= 256 bits (e.g., 256)	        100

    Total score: strongest cipher score + weakest cipher score, divided by 2.
    """
    NoEncryption = 0
    LessThan128 = 20
    LessThan256 = 80
    EqualOrGraterThan256 = 100


class MandatoryZeroFinalGrade(Enum):
    """
    For these reasons, any of the following immediately result in a zero score:
    """
    DOMAIN_MISS_MATCH = "domain name mismatch"                            # **V**
    CERTIFICATE_NOT_YET_VALID = "certificate not yet valid"               # **V**
    CERTIFICATE_EXPIRED = "certificate expired"                           # **V**
    CERTIFICATE_NOT_TRUSTED = "use of a certificate that is not trusted"  # **V** (unknown CA or other validation error)
    SSL20_SUPPORTED = "SSL2.0 is not allowed"                             # **V**
    OPENSSL_CCS_INJECTION_VULNERABILITY = "vulnerable to the openssl cve-2014-0224"     # **V**
    DROWN_VULNERABILITY = "vulnerable to DROWN"                           # **V**
    INSECURE_RENEGOTIATION = "server allowed insecure renegotiation"      # **V**
    # Use of a self-signed certificate
    # Use of a revoked certificate
    # Insecure certificate signature (MD2 or MD5)
    # Insecure key
    # (F) if server's best protocol is SSL 3.0
    # Keys under 1024 bits are now considered insecure (F).
    # MD5 certificate signatures is not allowed (F).
    # If vulnerable to the Ticketbleed (CVE-2016-9244), it will be given F.
    # If vulnerable to CVE-2016-2107 (Padding oracle in AES-NI CBC MAC check) it will be given F.
    # - SHA1 certificates are now longer trusted (T).
    # - WoSign/StartCom certificates distrusted, will get 'T' grade.


class FinalGradesCaps(Enum):
    """
       - **V** Servers that use SHA1 certificates can't get an A+. **V**
       - **V** Cap to C if vulnerable to POODLE. **V**
       - **V** Don’t award A+ to servers that don’t support TLS_FALLBACK_SCSV. **V**
       - Vulnerability to the BEAST attack caps the grade at B.
       - Vulnerability to the CRIME attack caps the grade at B.
       - Support for TLS 1.2 is now required to get the A grade. Without, the grade is capped a B.
       - Keys below 2048 bits (e.g., 1024) are now considered weak, and the grade capped at B.
       - Cap to B if SSL 3 is supported.
       - Cap to C if not supporting TLS 1.2.


    """
