from abc import abstractmethod

from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand


class TestCommand(object):
    """
    Abstract class to represent all available commands.
    This class is a wrapper for the original SSLyze scan commands.
    Once the command has been executed and the result has been parsed, a json object is ready for reading
    """
    scan_command = None
    scan_result = None
    json_result = None

    @classmethod
    @abstractmethod
    def get_json_result(cls):
        """
        This method should parse the scan_result attribute and build a json object.
        The json object should be build according to the 'server_rates.py' file with the appropriate grade
        :return: JSON
        """
        pass


class CertificateInfoTestCommand(TestCommand):

    def __init__(self):
        self.scan_command = CertificateInfoScanCommand()

    @classmethod
    def get_json_result(cls):
        if cls.scan_result is None:
            raise ScanResultUnavailable()



        pass


class ScanResultUnavailable(Exception):
    pass
