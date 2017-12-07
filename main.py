from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.server_connectivity import ServerConnectivityError
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv10ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv11ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv12ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv30ScanCommand
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from sslyze.plugins.compression_plugin import CompressionScanCommand
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanCommand
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanCommand
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanCommand
from sslyze.plugins.session_resumption_plugin import SessionResumptionSupportScanCommand
from sslyze.plugins.session_resumption_plugin import SessionResumptionRateScanCommand
from sslyze.synchronous_scanner import SynchronousScanner
import datetime
import sys


def print_results(scan_results, out_file):
    for res in scan_results.as_text():
        out_file.write(res+"\n")
    out_file.write("\n")


def run_command(scanner, server_info, command, output):
    print("[.] Checking {:50}".format(command.get_title()), end="")
    sys.stdout.flush()
    result = scanner.run_scan_command(server_info, command)
    print_results(result, output)
    print("DONE")


def main():

    if len(sys.argv) < 2:
        print("Error: please provide a domain")
        exit(-1)

    hostname = sys.argv[1]

    """
    Testing connectivity to the server
    """
    try:
        server_info = ServerConnectivityInfo(hostname)
        server_info.test_connectivity_to_server()
        print("[*] Connection established. \n[.] Starting tests on {} \n".format(hostname))
    except ServerConnectivityError as e:
        raise RuntimeError("Error when connecting to {}: {}".format(hostname, e.error_msg))

    scanner = SynchronousScanner()

    """
    Creating an output file
    """
    output = open(hostname, "w")
    output.write("##############################################\n")
    output.write("Output result for host: {}\n".format(hostname))
    output.write("Start {}\n".format(datetime.datetime.now()))
    output.write("##############################################\n\n")

    """
    Certificate:
    """
    scan_result = scanner.run_scan_command(server_info, CertificateInfoScanCommand())
    for e in scan_result.as_text():
        output.write(e+"\n")

    """
    Protocols and Ciphers Suits:
    """
    run_command(scanner, server_info, Tlsv10ScanCommand(), output)
    run_command(scanner, server_info, Tlsv11ScanCommand(), output)
    run_command(scanner, server_info, Tlsv12ScanCommand(), output)
    run_command(scanner, server_info, Sslv20ScanCommand(), output)
    run_command(scanner, server_info, Sslv30ScanCommand(), output)

    """
    Testing vulnerabilities:
    """
    run_command(scanner, server_info, HeartbleedScanCommand(), output)
    run_command(scanner, server_info, OpenSslCcsInjectionScanCommand(), output)
    run_command(scanner, server_info, CompressionScanCommand(), output)
    run_command(scanner, server_info, FallbackScsvScanCommand(), output)
    run_command(scanner, server_info, SessionRenegotiationScanCommand(), output)
    run_command(scanner, server_info, SessionResumptionSupportScanCommand(), output)
    run_command(scanner, server_info, SessionResumptionRateScanCommand(), output)

    """
    Closing
    """
    output.close()
    print("\n\n[*] Check output file for more details")
    print("[*] Test completed!")

if __name__ == '__main__':
    main()


