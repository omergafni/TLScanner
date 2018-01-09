import json
from commands.command import Command, ScanResultUnavailable
from plugins.drown_plugin import DrownScanCommand
from utils.server_rates import MandatoryZeroFinalGrade


class DrownCommand(Command):

    def __init__(self):
        super().__init__(DrownScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if self.scan_result.is_vulnerable_to_drown_attack:
            result[MandatoryZeroFinalGrade.DROWN_VULNERABILITY.value] = "final grade 0"
        else:
            result["drown vulnerability"] = "OK"

        return json.dumps(result)
