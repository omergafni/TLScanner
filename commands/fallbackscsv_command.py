import json
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanCommand
from commands.command import ScanResultUnavailable, Command


class FallbackScsvCommand(Command):

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
