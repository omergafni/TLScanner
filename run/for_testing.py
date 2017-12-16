from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand, Tlsv12ScanCommand, Sslv30ScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.synchronous_scanner import SynchronousScanner

from commands.test_commands import CipherSuitesTestCommand, CertificateInfoTestCommand

hostname = "www.nana10.co.il"

try:
    server_info = ServerConnectivityInfo(hostname)
    server_info.test_connectivity_to_server()
    print("[*] Connection established. \n[.] Starting tests on {} \n".format(hostname))
except ServerConnectivityError as e:
    raise RuntimeError("Error when connecting to {}: {}".format(hostname, e.error_msg))

scanner = SynchronousScanner()

cmnd = CertificateInfoTestCommand()
cmnd.scan_result = scanner.run_scan_command(server_info, cmnd.scan_command)

print(cmnd.get_result_as_json())
