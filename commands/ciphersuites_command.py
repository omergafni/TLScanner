import json

from commands.command import Command, ScanResultUnavailable
from utils.server_rates import ProtocolScoreEnum, CipherStrengthScoreEnum, MandatoryZeroFinalGrade, FinalGradeCaps


class CipherSuitesCommand(Command):

    protocol_scores = {"sslv3": ProtocolScoreEnum.SSLv30.value,
                       "tlsv1": ProtocolScoreEnum.TLSv10.value, "tlsv1_1": ProtocolScoreEnum.TLSv11.value,
                       "tlsv1_2": ProtocolScoreEnum.TLSv12.value, "tlsv1_3": ProtocolScoreEnum.TLSv13.value}

    cipher_strength_scores = {"0": CipherStrengthScoreEnum.NoEncryption.value,
                              "<128": CipherStrengthScoreEnum.LessThan128.value,
                              "<256": CipherStrengthScoreEnum.LessThan256.value,
                              ">=256": CipherStrengthScoreEnum.EqualOrGraterThan256.value}

    def __init__(self, cipher_scan_command):
        super().__init__(cipher_scan_command)

    @classmethod
    def get_cipher_strength_score(cls, min_cipher_key, max_cipher_key):
        if min_cipher_key == 0:
            min_score = cls.cipher_strength_scores["0"]
        elif min_cipher_key < 128:
            min_score = cls.cipher_strength_scores["<128"]
        elif min_cipher_key < 256:
            min_score = cls.cipher_strength_scores["<256"]
        else:  # min_cipher_key >= 256:
            min_score = cls.cipher_strength_scores[">=256"]

        if max_cipher_key == 0:
            max_score = cls.cipher_strength_scores["0"]
        elif max_cipher_key < 128:
            max_score = cls.cipher_strength_scores["<128"]
        elif max_cipher_key < 256:
            max_score = cls.cipher_strength_scores["<256"]
        else:  # max_cipher_key >= 256:
            max_score = cls.cipher_strength_scores[">=256"]

        return (max_score + min_score) / 2

    def get_result_as_json(self):
        result = {}
        supported_cipher_key_sizes = []

        if self.scan_result is None:
            raise ScanResultUnavailable()

        if len(self.scan_result.accepted_cipher_list) > 0:

            # Getting cipher suite score
            cipher_name = self.scan_command.get_cli_argument()
            if cipher_name == "sslv2":
                result[MandatoryZeroFinalGrade.SSL20_SUPPORTED.value] = "final grade 0"
            else:
                if cipher_name == "sslv3":
                    result[FinalGradeCaps.SSL3_SUPPORTED.value] = FinalGradeCaps.B.value

                result[cipher_name + '_protocol_score'] = self.protocol_scores[cipher_name]

                # Getting cipher strength score
                for cipher in self.scan_result.accepted_cipher_list:
                    supported_cipher_key_sizes.append(cipher.key_size)
                cipher_strength_score = self.get_cipher_strength_score(min(supported_cipher_key_sizes),
                                                                       max(supported_cipher_key_sizes))
                result[cipher_name + "_protocol_cipher_strength_score"] = cipher_strength_score
        else:
            pass  # No score to be added

        return json.dumps(result)
