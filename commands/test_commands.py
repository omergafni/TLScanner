import json
from abc import abstractmethod
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanCommand
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanCommand

from commands.server_rates import ProtocolScore, KeyExchangeScore, CipherStrengthScore
from plugins.drown_plugin import DrownScanCommand
from plugins.poodle_ssl_plugin import PoodleSslScanCommand


class TestCommand(object):
    """
    Abstract class to represent all available commands.
    This class is a wrapper for the original SSLyze scan commands.
    Once the command has been executed and the result has been parsed, a json object is ready for reading.
    """
    scan_result = None

    def __init__(self, scan_command):
        self.scan_command = scan_command

    @abstractmethod
    def get_result_as_json(self):
        """
        This method should parse the scan_result attribute and build a json object.
        The json object should be build according to the 'server_rates.py' file with the appropriate grade
        :return: JSON string
        """
        pass


class CertificateInfoTestCommand(TestCommand):
    def __init__(self):
        super().__init__(CertificateInfoScanCommand())
        self.key_exchange_scores = {"<512": KeyExchangeScore.LessThan512.value,
                                    "<1024": KeyExchangeScore.LessThan1024.value,
                                    "<2048": KeyExchangeScore.LessThan2048.value,
                                    "<4096": KeyExchangeScore.LessThan4096.value,
                                    ">=4096": KeyExchangeScore.EqualOrGreaterThan4096.value}

    def get_result_as_json(self):

        today = datetime.now()
        result = {}

        if self.scan_result is None:
            raise ScanResultUnavailable()

        # Using weak SHA1
        if self.scan_result.has_sha1_in_certificate_chain:
            result["certificate_info_sha1"] = "cap to A-"
        # Certificate hostname mismatch
        if not self.scan_result.certificate_matches_hostname:
            result["certificate_info_hostname_mismatch"] = "final grade: 0"
            return json.dumps(result)
        # Date validation
        for certificate in self.scan_result.certificate_chain:
            if certificate.not_valid_after < today:
                result["certificate_info_invalid_date"] = "final grade: 0"
                return json.dumps(result)
            if certificate.not_valid_before > today:
                result["certificate_info_invalid_date"] = "final grade: 0"
                return json.dumps(result)
        # Certificate is trusted?
        if not self.scan_result.verified_certificate_chain:
            result["certificate_info_not_trusted"] = "final grade: 0"
            return json.dumps(result)

        # Checking public key properties
        certificate = self.scan_result.certificate_chain[0]
        public_key = certificate.public_key()
        # necessary? -> public_key_algorithm = CertificateUtils.get_public_key_type(certificate)  # (e.g., RSA)
        # necessary? -> signature_algorithm_name = certificate.signature_hash_algorithm.name  # (e.g., sha256)
        if isinstance(public_key, EllipticCurvePublicKey):
            key_size = public_key.curve.key_size
        else:
            key_size = public_key.key_size

        if key_size < 512:
            result["key_exchange_score"] = self.key_exchange_scores["<512"]
        elif key_size < 1024:
            result["key_exchange_score"] = self.key_exchange_scores["<1024"]
        elif key_size < 2048:
            result["key_exchange_score"] = self.key_exchange_scores["<2048"]
        elif key_size < 4096:
            result["key_exchange_score"] = self.key_exchange_scores["<4096"]
        elif key_size >= 4096:
            result["key_exchange_score"] = self.key_exchange_scores[">=4096"]

        return json.dumps(result)


class CipherSuitesTestCommand(TestCommand):

    protocol_scores = {"sslv2": ProtocolScore.SSLv20.value, "sslv3": ProtocolScore.SSLv30.value,
                       "tlsv1": ProtocolScore.TLSv10.value, "tlsv1_1": ProtocolScore.TLSv11.value,
                       "tlsv1_2": ProtocolScore.TLSv12.value}

    cipher_strength_scores = {"0": CipherStrengthScore.NoEncryption.value,
                              "<128": CipherStrengthScore.LessThan128.value,
                              "<256": CipherStrengthScore.LessThan256.value,
                              ">=256": CipherStrengthScore.EqualOrGraterThan256.value}

    def __init__(self, cipher_scan_command):
        super().__init__(cipher_scan_command)

    @classmethod
    def get_cipher_strength_score(cls, min_cipher_key, max_cipher_key):
        min_score = -1
        max_score = -1
        if min_cipher_key == 0:
            min_score = cls.cipher_strength_scores["0"]
        elif min_cipher_key < 128:
            min_score = cls.cipher_strength_scores["<128"]
        elif min_cipher_key < 256:
            min_score = cls.cipher_strength_scores["<256"]
        elif min_cipher_key >= 256:
            min_score = cls.cipher_strength_scores[">=256"]

        if max_cipher_key == 0:
            max_score = cls.cipher_strength_scores["0"]
        elif max_cipher_key < 128:
            max_score = cls.cipher_strength_scores["<128"]
        elif max_cipher_key < 256:
            max_score = cls.cipher_strength_scores["<256"]
        elif max_cipher_key >= 256:
            max_score = cls.cipher_strength_scores[">=256"]

        if min_score != -1 and max_score != -1:
            return (max_score + min_score) / 2
        else:
            raise CipherStrengthScoreUnavailable()

    def get_result_as_json(self):

        result = {}
        supported_cipher_key_sizes = []

        if self.scan_result is None:
            raise ScanResultUnavailable()

        if len(self.scan_result.accepted_cipher_list) > 0:

            # Getting cipher suite score
            cipher_name = self.scan_command.get_cli_argument()
            result[cipher_name + '_score'] = self.protocol_scores[cipher_name]

            # Getting cipher strength score
            for cipher in self.scan_result.accepted_cipher_list:
                supported_cipher_key_sizes.append(cipher.key_size)
            cipher_strength_score = self.get_cipher_strength_score(min(supported_cipher_key_sizes),
                                                                   max(supported_cipher_key_sizes))
            result["cipher_strength_score"] = cipher_strength_score
        else:
            pass  # No score to be added

        return json.dumps(result)


class PoodleSslTestCommand(TestCommand):

    def __init__(self):
        super().__init__(PoodleSslScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if self.scan_result.is_vulnerable_to_poodle_ssl:
            result["poodle_vulnerability"] = "cap to C"
        else:
            result["poodle_vulnerability"] = "OK"

        return json.dumps(result)


class DrownTestCommand(TestCommand):

    def __init__(self):
        super().__init__(DrownScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if self.scan_result.is_vulnerable_to_drown_attack:
            result["drown_vulnerability"] = "grade F"
        else:
            result["drown_vulnerability"] = "OK"

        return json.dumps(result)


class HeartbleedTestCommand(TestCommand):

    def __init__(self):
        super().__init__(HeartbleedScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if self.scan_result.is_vulnerable_to_heartbleed:
            result["heartbleed_vulnerability"] = "grade F"
        else:
            result["heartbleed_vulnerability"] = "OK"

        return json.dumps(result)


class OpenSslCcsInjectionTestCommand(TestCommand):

    def __init__(self):
        super().__init__(OpenSslCcsInjectionScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if self.scan_result.is_vulnerable_to_ccs_injection:
            result["openssl_ccs_injection"] = "grade F"
        else:
            result["openssl_ccs_injection"] = "OK"

        return json.dumps(result)


class ScanResultUnavailable(Exception):
    pass


class FallbackScsvTestCommand(TestCommand):

    def __init__(self):
        super().__init__(FallbackScsvScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if not self.scan_result.supports_fallback_scsv:
            result["supports_fallback_scsv"] = "cap to A-"
        else:
            result["supports_fallback_scsv"] = "OK"

        return json.dumps(result)


class CipherStrengthScoreUnavailable(Exception):
    pass
