from abc import abstractmethod


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


class ScanResultUnavailable(Exception):
    pass


class CipherStrengthScoreUnavailable(Exception):
    pass
