from nassl.ssl_client import OpenSslVersionEnum
from sslyze.plugins import plugin_base
from sslyze.plugins.plugin_base import PluginScanCommand, PluginScanResult
from sslyze.utils.ssl_connection import SSLHandshakeRejected


class PoodleScanCommand(PluginScanCommand):
    """
    Test the server(s) for the POODLE SSL vulnerability (CVE-2014-3566).
    """

    @classmethod
    def get_cli_argument(cls):
        return 'poodle'

    @classmethod
    def get_title(cls):
        return 'POODLE, SSL (CVE-2014-3566)'


class PoodleSslPlugin(plugin_base.Plugin):
    """
    Test the server(s) for the POODLE SSL vulnerability.
    """

    @classmethod
    def get_available_commands(cls):
        return [PoodleScanCommand]

    def process_task(self, server_info, scan_command):

        is_vulnerable_to_poodle_ssl = True
        ssl_connection = server_info.get_preconfigured_ssl_connection(
            override_ssl_version=OpenSslVersionEnum.SSLV3
            # should_use_legacy_openssl=True
        )
        try:
            # Perform the SSL handshake
            ssl_connection.connect()
            # ? cipher_result = AcceptedCipherSuite.from_ongoing_ssl_connection(ssl_connection, ssl_version)

        except SSLHandshakeRejected:
            is_vulnerable_to_poodle_ssl = False

        finally:
            ssl_connection.close()

        return PoodleScanResult(server_info, scan_command, is_vulnerable_to_poodle_ssl)


class PoodleScanResult(PluginScanResult):
    """The result of running a PoodleScanCommand on a specific server.

    Attributes:
        is_vulnerable_to_poodle_ssl (bool): True if the server is vulnerable to the POODLE attack over ssl.
    """

    def __init__(self, server_info, scan_command, is_vulnerable_to_poodle_ssl):
        super(PoodleScanResult, self).__init__(server_info, scan_command)
        self.is_vulnerable_to_poodle_ssl = is_vulnerable_to_poodle_ssl

    def as_text(self):
        poodle_txt = 'VULNERABLE - Server is vulnerable to POODLE, SSL (CVE-2014-3566)' \
            if self.is_vulnerable_to_poodle_ssl \
            else 'OK - Not vulnerable to POODLE, SSL (CVE-2014-3566)'

        return [self._format_title(self.scan_command.get_title()), self._format_field('', poodle_txt)]

    def as_xml(self):
        pass


