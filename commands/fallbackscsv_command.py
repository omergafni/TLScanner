import json
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanCommand
from commands.testcommand import ScanResultUnavailable, TestCommand


class FallbackScsvTestCommand(TestCommand):

    def __init__(self):
        super().__init__(FallbackScsvScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if not self.scan_result.supports_fallback_scsv:
            result["supports_fallback_scsv"] = "cap to A-"
        else:
            result["supports_fallback_scsv"] = "OK"

        return json.dumps(result)
