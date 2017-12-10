import json
from datetime import datetime
from abc import abstractmethod

from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand


class TestCommand(object):
    """
    Abstract class to represent all available commands.
    This class is a wrapper for the original SSLyze scan commands.
    Once the command has been executed and the result has been parsed, a json object is ready for reading
    """
    scan_result = None

    def __init__(self, scan_command):
        self.scan_command = scan_command

    @classmethod
    @abstractmethod
    def get_result_as_json(cls):
        """
        This method should parse the scan_result attribute and build a json object.
        The json object should be build according to the 'server_rates.py' file with the appropriate grade
        :return: JSON
        """
        pass


class CertificateInfoTestCommand(TestCommand):

    def __init__(self):
        super().__init__(CertificateInfoScanCommand())

    @classmethod
    def get_result_as_json(cls):

        today = datetime.now()
        result = {}

        if cls.scan_result is None:
            raise ScanResultUnavailable()
        else:
            # Using weak SHA1
            if cls.scan_result.has_sha1_in_certificate_chain:
                result["certificate_info_sha1"] = "no A+"
            # Certificate hostname mismatch
            if not cls.scan_result.certificate_matches_hostname:
                result["certificate_info_hostname_mismatch"] = "grade 0"
            # Date validation
            for certificate in cls.scan_result.certificate_chain:
                if certificate.not_valid_after < today:
                    result["certificate_info_invalid_date"] = "grade 0"
                if certificate.not_valid_before > today:
                    result["certificate_info_invalid_date"] = "grade 0"
            # Certificate is trusted?
            if not cls.scan_result.verified_certificate_chain:
                result["certificate_info_not_trusted"] = "grade 0"

            return json.dumps(result)


class ScanResultUnavailable(Exception):
    pass
