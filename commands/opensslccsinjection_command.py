import json
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanCommand
from commands.command import ScanResultUnavailable, Command


class OpenSslCcsInjectionCommand(Command):

    def __init__(self):
        super().__init__(OpenSslCcsInjectionScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if self.scan_result.is_vulnerable_to_ccs_injection:
            result["openssl_ccs_injection"] = "grade F"
        else:
            result["openssl_ccs_injection"] = "OK"

        return json.dumps(result)
