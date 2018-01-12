import json
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from commands.command import Command, ScanResultUnavailable
from utils.server_rates import MandatoryZeroFinalGrade


class HeartbleedCommand(Command):

    def __init__(self):
        super().__init__(HeartbleedScanCommand())

    def get_result_as_json(self):

        result = {}

        if self.scan_result is None:
            raise ScanResultUnavailable()

        if self.scan_result.is_vulnerable_to_heartbleed:
            result[MandatoryZeroFinalGrade.HEARTBLEED_VULNERABILITY.value] = "final grade 0"
        else:
            result["heartbleed_vulnerability_scan_result"] = "ok"

        return json.dumps(result)
