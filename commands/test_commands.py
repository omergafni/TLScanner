import json
from abc import abstractmethod
from datetime import datetime
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from commands.server_rates import ProtocolScore


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

    def get_result_as_json(self):

        today = datetime.now()
        result = {}

        if self.scan_result is None:
            raise ScanResultUnavailable()
        else:
            # Using weak SHA1
            if self.scan_result.has_sha1_in_certificate_chain:
                result["certificate_info_sha1"] = "no A+"
            # Certificate hostname mismatch
            if not self.scan_result.certificate_matches_hostname:
                result["certificate_info_hostname_mismatch"] = "final grade: 0"
            # Date validation
            for certificate in self.scan_result.certificate_chain:
                if certificate.not_valid_after < today:
                    result["certificate_info_invalid_date"] = "final grade: 0"
                if certificate.not_valid_before > today:
                    result["certificate_info_invalid_date"] = "final grade: 0"
            # Certificate is trusted?
            if not self.scan_result.verified_certificate_chain:
                result["certificate_info_not_trusted"] = "final grade: 0"

            return json.dumps(result)


class CipherSuitesTestCommand(TestCommand):

    def __init__(self, cipher_scan_command):
        super().__init__(cipher_scan_command)

    def get_result_as_json(self):

        result = {}
        scores = {"sslv2": ProtocolScore.SSLv20.value, "sslv3": ProtocolScore.SSLv30.value,
                  "tlsv1": ProtocolScore.TLSv10.value, "tlsv1_1": ProtocolScore.TLSv11.value,
                  "tlsv1_2": ProtocolScore.TLSv12.value}

        if self.scan_result is None:
            raise ScanResultUnavailable()
        else:
            if len(self.scan_result.accepted_cipher_list) > 0:
                cipher_name = self.scan_command.get_cli_argument()
                result[cipher_name + ' score'] = scores[cipher_name]
            else:
                pass  # No score to be added

        return json.dumps(result)


class ScanResultUnavailable(Exception):
    pass
