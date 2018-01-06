import json
from commands.command import Command, ScanResultUnavailable
from plugins.drown_plugin import DrownScanCommand


class DrownCommand(Command):

    def __init__(self):
        super().__init__(DrownScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if self.scan_result.is_vulnerable_to_drown_attack:
            result["drown_vulnerability"] = "grade F"
        else:
            result["drown_vulnerability"] = "OK"

        return json.dumps(result)
