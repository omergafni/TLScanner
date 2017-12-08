from nassl.ssl_client import OpenSslVersionEnum
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanCommand, PluginScanResult
from sslyze.utils.ssl_connection import SSLHandshakeRejected


class DrownScanCommand(PluginScanCommand):
    """
    Test the server(s) for the DROWN vulnerability (CVE-2016-0800).
    """

    @classmethod
    def get_cli_argument(cls):
        return 'drown'

    @classmethod
    def get_title(cls):
        return 'DROWN (CVE-2016-0800)'


class DrownPlugin(plugin_base.Plugin):
    """
    Test the server(s) for the DROWN attack vulnerability.
    """

    @classmethod
    def get_available_commands(cls):
        return [DrownScanCommand]

    def process_task(self, server_info, scan_command):

        is_vulnerable_to_drown_attack = True
        ssl_connection = server_info.get_preconfigured_ssl_connection(
            override_ssl_version=OpenSslVersionEnum.SSLV2
            # should_use_legacy_openssl=True
        )
        try:
            # Perform the SSL handshake
            ssl_connection.connect()
            # ? cipher_result = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)

        except SSLHandshakeRejected:
            is_vulnerable_to_drown_attack = False

        finally:
            ssl_connection.close()

        return DrownScanResult(server_info, scan_command, is_vulnerable_to_drown_attack)


class DrownScanResult(PluginScanResult):
    """The result of running a DrownScanCommand on a specific server.

    Attributes:
        is_vulnerable_to_drown_attack (bool): True if the server is vulnerable to the DROWN attack.
    """

    def __init__(self, server_info, scan_command, is_vulnerable_to_drown_attack):
        super(DrownScanResult, self).__init__(server_info, scan_command)
        self.is_vulnerable_to_drown_attack= is_vulnerable_to_drown_attack

    def as_text(self):
        drown_txt = 'VULNERABLE - Server is vulnerable to DROWN (CVE-2016-0800)' \
            if self.is_vulnerable_to_drown_attack \
            else 'OK - Not vulnerable to DROWN (CVE-2016-0800)'

        return [self._format_title(self.scan_command.get_title()), self._format_field('', drown_txt)]

    def as_xml(self):
        pass


