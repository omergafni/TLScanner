import json
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanCommand
from commands.command import ScanResultUnavailable, Command
from utils.server_rates import FinalGradeCaps


class FallbackScsvCommand(Command):

    def __init__(self):
        super().__init__(FallbackScsvScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if not self.scan_result.supports_fallback_scsv:
            result[FinalGradeCaps.TLS_FALLBACK_SCSV_NOT_SUPPORTED.value] = FinalGradeCaps.A_MINUS.value
        else:
            result["supports_fallback_scsv_scan_result"] = "ok"

        return json.dumps(result)
