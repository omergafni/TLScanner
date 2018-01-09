import json
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanCommand
from commands.command import Command, ScanResultUnavailable
from utils.server_rates import MandatoryZeroFinalGrade


class SessionRenegotiationCommand(Command):

    def __init__(self):
        super().__init__(SessionRenegotiationScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if not self.scan_result.supports_secure_renegotiation:
            result[MandatoryZeroFinalGrade.INSECURE_RENEGOTIATION.value] = "final grade 0"
        else:
            result["secure renegotiation vulnerability"] = "OK"

        # TODO: 'accepts_client_renegotiation' can be also checked here

        return json.dumps(result)

