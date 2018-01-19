import datetime
import json
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from commands.command import Command, ScanResultUnavailable
from utils.server_rates import KeyExchangeScoreEnum, MandatoryZeroFinalGrade, FinalGradeCaps


class CertificateInfoCommand(Command):

    def __init__(self):
        super().__init__(CertificateInfoScanCommand())
        self.key_exchange_scores = {"<512": KeyExchangeScoreEnum.LessThan512.value,
                                    "<1024": KeyExchangeScoreEnum.LessThan1024.value,
                                    "<2048": KeyExchangeScoreEnum.LessThan2048.value,
                                    "<4096": KeyExchangeScoreEnum.LessThan4096.value,
                                    ">=4096": KeyExchangeScoreEnum.EqualOrGreaterThan4096.value}

    def get_result_as_json(self):

        today = datetime.datetime.now()
        today_plus_30 = today + datetime.timedelta(+30)
        today_plus_7 = today + datetime.timedelta(+7)
        result = {}

        if self.scan_result is None:
            raise ScanResultUnavailable()

        # Using weak SHA1
        if self.scan_result.has_sha1_in_certificate_chain:
            result[FinalGradeCaps.AMinusCap.USING_SHA1_CERTIFICATE.value] = FinalGradeCaps.Caps.A_MINUS.value

        # Certificate hostname mismatch
        if not self.scan_result.certificate_matches_hostname:
            result[MandatoryZeroFinalGrade.DOMAIN_MISS_MATCH.value] = "final grade 0"
            return json.dumps(result)

        # Date validation
        for certificate in self.scan_result.certificate_chain:
            if certificate.not_valid_after < today:
                result[MandatoryZeroFinalGrade.CERTIFICATE_EXPIRED.value] = "final grade 0"
                return json.dumps(result)
            if certificate.not_valid_before > today:
                result[MandatoryZeroFinalGrade.CERTIFICATE_NOT_YET_VALID.value] = "final grade 0"
                return json.dumps(result)
            if certificate.not_valid_after < today_plus_7:
                result["certificate_date_validation_warning"] = "expired in 7 days or less"
            elif certificate.not_valid_after < today_plus_30:
                result["certificate_date_validation_caution"] = "expired in 30 days or less"

        # Certificate is trusted?
        if not self.scan_result.verified_certificate_chain:
            result[MandatoryZeroFinalGrade.CERTIFICATE_NOT_TRUSTED.value] = "final grade 0"
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
            result["certificate_key_exchange_score"] = self.key_exchange_scores["<512"]
            result[MandatoryZeroFinalGrade.KEY_UNDER_1024.value] = "final grade 0"
        elif key_size < 1024:
            result["certificate_key_exchange_score"] = self.key_exchange_scores["<1024"]
            result[MandatoryZeroFinalGrade.KEY_UNDER_1024.value] = "final grade 0"
        elif key_size < 2048:
            result["certificate_key_exchange_score"] = self.key_exchange_scores["<2048"]
        elif key_size < 4096:
            result["certificate_key_exchange_score"] = self.key_exchange_scores["<4096"]
        else:  # key_size >= 4096:
            result["certificate_key_exchange_score"] = self.key_exchange_scores[">=4096"]

        return json.dumps(result)
