import sys

from sslyze.plugins.robot_plugin import RobotScanCommand

from commands.certificateinfo_command import CertificateInfoCommand
from commands.ciphersuites_command import CipherSuitesCommand
from commands.drown_command import DrownCommand
from commands.fallbackscsv_command import FallbackScsvCommand
from commands.heartbleed_command import HeartbleedCommand
from commands.opensslccsinjection_command import OpenSslCcsInjectionCommand
from commands.poodlessl_command import PoodleSslCommand

sys.path.append("/root/PycharmProjects/SSL-TLS-Tool")

from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand, Tlsv12ScanCommand, Sslv30ScanCommand, \
    Tlsv10ScanCommand, Tlsv11ScanCommand
from sslyze.server_connectivity import ServerConnectivityInfo, ServerConnectivityError
from sslyze.synchronous_scanner import SynchronousScanner


hostname = "mohconsole.health.gov.il"

try:
    server_info = ServerConnectivityInfo(hostname)
    server_info.test_connectivity_to_server()
    print("[*] Connection established. \n[.] Starting tests on {} \n".format(hostname))
except ServerConnectivityError as e:
    raise RuntimeError("Error when connecting to {}: {}".format(hostname, e.error_msg))

scanner = SynchronousScanner()

result = scanner.run_scan_command(server_info, RobotScanCommand())

cmnd = CertificateInfoCommand()
cmnd.scan_result = scanner.run_scan_command(server_info, cmnd.scan_command)
print(cmnd.get_result_as_json())

cmnd = CipherSuitesCommand(Tlsv12ScanCommand())
cmnd.scan_result = scanner.run_scan_command(server_info, cmnd.scan_command)
print(cmnd.get_result_as_json())

cmnd = CipherSuitesCommand(Tlsv11ScanCommand())
cmnd.scan_result = scanner.run_scan_command(server_info, cmnd.scan_command)
print(cmnd.get_result_as_json())

cmnd = CipherSuitesCommand(Tlsv10ScanCommand())
cmnd.scan_result = scanner.run_scan_command(server_info, cmnd.scan_command)
print(cmnd.get_result_as_json())

cmnd = CipherSuitesCommand(Sslv20ScanCommand())
cmnd.scan_result = scanner.run_scan_command(server_info, cmnd.scan_command)
print(cmnd.get_result_as_json())

cmnd = CipherSuitesCommand(Sslv30ScanCommand())
cmnd.scan_result = scanner.run_scan_command(server_info, cmnd.scan_command)
print(cmnd.get_result_as_json())

cmnd = PoodleSslCommand()
cmnd.scan_result = scanner.run_scan_command(server_info, cmnd.scan_command)
print(cmnd.get_result_as_json())

cmnd = OpenSslCcsInjectionCommand()
cmnd.scan_result = scanner.run_scan_command(server_info, cmnd.scan_command)
print(cmnd.get_result_as_json())

cmnd = HeartbleedCommand()
cmnd.scan_result = scanner.run_scan_command(server_info, cmnd.scan_command)
print(cmnd.get_result_as_json())

cmnd = DrownCommand()
cmnd.scan_result = scanner.run_scan_command(server_info, cmnd.scan_command)
print(cmnd.get_result_as_json())

cmnd = FallbackScsvCommand()
cmnd.scan_result = scanner.run_scan_command(server_info, cmnd.scan_command)
print(cmnd.get_result_as_json())
