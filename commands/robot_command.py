import json

from sslyze.plugins.robot_plugin import RobotScanCommand, RobotScanResultEnum

from commands.command import Command, ScanResultUnavailable


class RobotCommand(Command):

    def __init__(self):
        super().__init__(RobotScanCommand())

    def get_result_as_json(self):

        result = {}

        if self.scan_result is None:
            raise ScanResultUnavailable()

        if self.scan_result.robot_result_enum == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE:
            result["robot_scan_result"] = 'vulnerable_strong_oracle'
        elif self.scan_result.robot_result_enum == RobotScanResultEnum.VULNERABLE_WEAK_ORACLE:
            result["robot_scan_result"] = 'vulnerable_weak oracle'
        elif self.scan_result.robot_result_enum == RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE:
            result["robot_scan_result"] = 'ok'
        elif self.scan_result.robot_result_enum == RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED:
            result["robot_scan_result"] = 'ok'
        else:  # robot_result_enum == RobotScanResultEnum.UNKNOWN_INCONSISTENT_RESULTS:
            result["robot_scan_result"] = 'unknown'

        return json.dumps(result)
