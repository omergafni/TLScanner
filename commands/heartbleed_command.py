import json
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand
from commands.testcommand import TestCommand, ScanResultUnavailable


class HeartbleedTestCommand(TestCommand):

    def __init__(self):
        super().__init__(HeartbleedScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if self.scan_result.is_vulnerable_to_heartbleed:
            result["heartbleed_vulnerability"] = "grade F"
        else:
            result["heartbleed_vulnerability"] = "OK"

        return json.dumps(result)
