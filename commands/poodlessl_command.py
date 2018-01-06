import json
from commands.command import Command, ScanResultUnavailable
from plugins.poodlessl_plugin import PoodleSslScanCommand


class PoodleSslCommand(Command):

    def __init__(self):
        super().__init__(PoodleSslScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if self.scan_result.is_vulnerable_to_poodle_ssl:
            result["poodle_vulnerability"] = "cap to C"
        else:
            result["poodle_vulnerability"] = "OK"

        return json.dumps(result)