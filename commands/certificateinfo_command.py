import datetime
import json
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from commands.testcommand import TestCommand, ScanResultUnavailable
from utils.server_rates import KeyExchangeScoreEnum


class CertificateInfoTestCommand(TestCommand):

    def __init__(self):
        super().__init__(CertificateInfoScanCommand())
        self.key_exchange_scores = {"<512": KeyExchangeScoreEnum.LessThan512.value,
                                    "<1024": KeyExchangeScoreEnum.LessThan1024.value,
                                    "<2048": KeyExchangeScoreEnum.LessThan2048.value,
                                    "<4096": KeyExchangeScoreEnum.LessThan4096.value,
                                    ">=4096": KeyExchangeScoreEnum.EqualOrGreaterThan4096.value}

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
        else: # key_size >= 4096:
            result["key_exchange_score"] = self.key_exchange_scores[">=4096"]

        return json.dumps(result)
