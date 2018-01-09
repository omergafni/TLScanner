import sys
sys.path.append("/root/PycharmProjects/SSL-TLS-Tool")

import datetime
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv30ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv10ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv11ScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Tlsv12ScanCommand
from sslyze.server_connectivity import ServerConnectivityError
from sslyze.server_connectivity import ServerConnectivityInfo
from sslyze.synchronous_scanner import SynchronousScanner

from commands.certificateinfo_command import CertificateInfoCommand
from commands.ciphersuites_command import CipherSuitesCommand
from commands.drown_command import DrownCommand
from commands.fallbackscsv_command import FallbackScsvCommand
from commands.heartbleed_command import HeartbleedCommand
from commands.opensslccsinjection_command import OpenSslCcsInjectionCommand
from commands.poodlessl_command import PoodleSslCommand
from commands.sessionrenegotiation_command import SessionRenegotiationCommand
from utils.results_parser import ResultsParser


def print_results(scan_results, out_file):
    for res in scan_results.as_text():
        out_file.write(res+"\n")
    out_file.write("\n")


def run_command(scanner, server_info, command, output):
    print("[.] Checking {:50}".format(command.scan_command.get_title()), end="")
    sys.stdout.flush()
    command.scan_result = scanner.run_scan_command(server_info, command.scan_command)
    print_results(command.scan_result, output)
    print("DONE")
    return command.get_result_as_json()


def create_output_file(hostname):
    output = open("output/"+hostname, "w")
    output.write("##############################################\n")
    output.write("Output result for host: {}\n".format(hostname))
    output.write("Start {}\n".format(datetime.datetime.now()))
    output.write("##############################################\n\n")
    return output


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
        print("[*] Connection established. \n[*] Starting tests on {} \n".format(hostname))
    except ServerConnectivityError as e:
        raise RuntimeError("Error when connecting to {}: {}".format(hostname, e.error_msg))

    scanner = SynchronousScanner()
    output = create_output_file(hostname)

    """ 
    Commands lists:
    """
    cipher_suites_commands = [CipherSuitesCommand(Tlsv10ScanCommand()),
                              CipherSuitesCommand(Tlsv11ScanCommand()),
                              CipherSuitesCommand(Tlsv12ScanCommand()),
                              CipherSuitesCommand(Sslv20ScanCommand()),
                              CipherSuitesCommand(Sslv30ScanCommand())]

    # TODO: CompressionCommand(), SessionResumptionSupportCommand(), SessionResumptionRateScanCommand()
    vulnerabilities_commands = [DrownCommand(), PoodleSslCommand(), HeartbleedCommand(),
                                OpenSslCcsInjectionCommand(),
                                FallbackScsvCommand(), SessionRenegotiationCommand()]

    """
    Run commands:
    """
    json_results = [run_command(scanner, server_info, CertificateInfoCommand(), output)]

    for cipher_suite in cipher_suites_commands:
        json_results.append(run_command(scanner, server_info, cipher_suite, output))

    for vulnerability in vulnerabilities_commands:
        json_results.append(run_command(scanner, server_info, vulnerability, output))

    """
    Parsing results:
    """
    results_parser = ResultsParser()
    results_parser.sort_and_parse_json_results(json_results)
    print("\n[*] Server result: {}".format(results_parser.get_final_results()))

    """
    Closing
    """
    output.close()
    print("[*] Check output file for more details")
    print("\n[*] Test completed! exiting now.")


if __name__ == '__main__':
    # sys.path.append("/root/PycharmProjects/SSL-TLS-Tool/plugins")
    main()


