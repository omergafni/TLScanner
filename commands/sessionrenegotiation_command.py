import json
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanCommand
from commands.testcommand import TestCommand, ScanResultUnavailable


class SessionRenegotiationTestCommand(TestCommand):

    def __init__(self):
        super().__init__(SessionRenegotiationScanCommand())

    def get_result_as_json(self):
        result = {}
        if self.scan_result is None:
            raise ScanResultUnavailable()

        if not self.scan_result.supports_secure_renegotiation:
            result["secure_renegotiation_unsupported"] = "grade F"
        else:
            result["secure_renegotiation_supported"] = "OK"

        # TODO: 'accepts_client_renegotiation' can be also checked here

        return json.dumps(result)

