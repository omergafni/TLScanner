from enum import Enum


class GradesEnum(object):
    """
    Letter grade translation:
    A - if score >= 80
    B - if score >= 65
    C - if score >= 50
    D - if score >= 35
    E - if score >= 20
    F - if score <  20

    Total grade will be a combination of: Protocol support, key exchange, cipher strength scores.

    ** Implementation is in ResultsParser class **
    """
    class GradeValue(Enum):
        A = 80
        B = 65
        C = 50
        D = 35
        E = 20
        F = 0

    class GradeFactor(Enum):
        PROTOCOL_FACTOR = 0.3
        KEY_FACTOR = 0.3
        CIPHER_FACTOR = 0.4

    class GradeDescription(Enum):
        A_PLUS = "A+ >> good configuration, no warnings."
        A_MINUS = "A- >> good configuration that have one or more warnings."
        B = "B >> "  # + parser's description message
        C = "C >> "  # + parser's description message
        D = "D >> "  # + parser's description message
        E = "E >> "  # + parser's description message
        F = "F >> Server failed: "  # + parser's description message
        T = "T >> site certificate is not trusted."


class ProtocolScoreEnum(Enum):
    """
    Protocol support:
        SSL 2.0:	0
        SSL 3.0:	80
        TLS 1.0:	90
        TLS 1.1:	95
        TLS 1.2:	100

        Total score: best protocol score + worst protocol score, divided by 2.
    """
    # SSLv20 = 0 - resulting mandatory F final grade
    SSLv30 = 80
    TLSv10 = 90
    TLSv11 = 95
    TLSv12 = 100
    TLSv13 = 100  # TODO: refactoring scores after tls13 support


class KeyExchangeScoreEnum(Enum):
    """
    Key exchange:
        Weak key (Debian OpenSSL flaw): 	                         0  # TODO: implement
        Anonymous key exchange (no authentication)	                 0  # TODO: implement
        Exportable key exchange (limited to 512 bits)	             40 # TODO: implement
    """
    # RSA & Diffie-Hellman keys:
    LessThan512 = 20
    LessThan1024 = 40
    LessThan2048 = 80
    LessThan4096 = 90
    EqualOrGreaterThan4096 = 100

    # Elliptic Curve keys:
    EC_LessThan160 = 20
    EC_LessThan224 = 40
    EC_LessThan256 = 80
    EC_LessThan384 = 90
    EC_EqualOrGreaterThan384 = 100


class CipherStrengthScoreEnum(Enum):
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
    Any of the following immediately result in a zero score:
    """
    DOMAIN_MISS_MATCH = "domain name mismatch"
    CERTIFICATE_NOT_YET_VALID = "certificate not yet valid"
    CERTIFICATE_EXPIRED = "certificate expired"
    CERTIFICATE_NOT_TRUSTED = "use of a certificate that is not trusted"  # (unknown CA or other validation error)
    SSL20_SUPPORTED = "SSL2.0 is not allowed"
    OPENSSL_CCS_INJECTION_VULNERABILITY = "vulnerable to the openssl cve-2014-0224"
    DROWN_VULNERABILITY = "vulnerable to DROWN"
    INSECURE_RENEGOTIATION = "server allowed insecure renegotiation"
    KEY_UNDER_1024 = "server's key is insecure (below 1024 bits)"
    HEARTBLEED_VULNERABILITY = "vulnerable to Heartbleed"

    # TODO: implementation for the list below:
    # Use of a self-signed certificate
    # Use of a revoked certificate
    # Insecure certificate signature (MD2 or MD5)
    # Insecure key
    # (F) if server's best protocol is SSL 3.0
    # MD5 certificate signatures is not allowed (F).
    # If vulnerable to the Ticketbleed (CVE-2016-9244), it will be given F.
    # If vulnerable to CVE-2016-2107 (Padding oracle in AES-NI CBC MAC check) it will be given F.
    # - SHA1 certificates are now longer trusted (T).
    # - WoSign/StartCom certificates distrusted, will get 'T' grade.


class FinalGradeCaps(Enum):

    A_MINUS = "cap to A-"
    B = "cap to B"
    C = "cap to C"
    D = "cap to D"
    E = "cap to E"

    """
    Any of the following will cause a final grades constraint:
    """
    # A- caps:
    USING_SHA1_CERTIFICATE = "server uses SHA1 certificate"
    TLS_FALLBACK_SCSV_NOT_SUPPORTED = "server does not support TLS_FALLBACK_SCSV"  # A- cap

    # B caps:
    SSL3_SUPPORTED = "server supports SSL 3.0"
    KEY_BELOW_2048 = "public key below 2048 bits"

    # C caps:
    POODLE_VULNERABILITY = "vulnerable to POODLE"

    # TODO: implementation for the list below:
    # Vulnerability to the BEAST attack caps the grade at B.
    # Vulnerability to the CRIME attack caps the grade at B.
    # Support for TLS 1.2 is now required to get the A grade. Without, the grade is capped a B.
    # Keys below 2048 bits (e.g., 1024) are now considered weak, and the grade capped at B.
    # Cap to C if not supporting TLS 1.2.
