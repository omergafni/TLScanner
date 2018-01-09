import json

from utils.server_rates import GradesEnum, MandatoryZeroFinalGrade


class ResultsParser(object):
    """
    This class responsibility is to parse the final json results getting by all the scan commands.
    The class final outcome is the scan summarize and the final server's grade.
    """
    final_grades_repository = {">=80": GradesEnum.A_PLUS.value,  # TODO: A+/-
                               ">=65": GradesEnum.B.value,
                               ">=50": GradesEnum.C.value,
                               ">=35": GradesEnum.D.value,
                               ">=20": GradesEnum.E.value,
                               "<20": GradesEnum.F.value}

    mandatory_zero_repository = [MandatoryZeroFinalGrade.CERTIFICATE_NOT_TRUSTED.value,
                                 MandatoryZeroFinalGrade.CERTIFICATE_NOT_YET_VALID.value,
                                 MandatoryZeroFinalGrade.CERTIFICATE_EXPIRED.value,
                                 MandatoryZeroFinalGrade.DOMAIN_MISS_MATCH.value,
                                 MandatoryZeroFinalGrade.SSL20_SUPPORTED.value,
                                 MandatoryZeroFinalGrade.OPENSSL_CCS_INJECTION_VULNERABILITY.value,
                                 MandatoryZeroFinalGrade.DROWN_VULNERABILITY.value,
                                 MandatoryZeroFinalGrade.INSECURE_RENEGOTIATION.value]

    def __init__(self):
        self.certificate_results = {}
        self.cipher_suites_results = {}
        self.vulnerabilities_results = {}
        self.mandatory_zero_final_results = {}

    def sort_and_parse_json_results(self, json_results):

        results = {}
        for json_result in json_results:
            results.update(json.loads(json_result))

        for result in results:
            if result in self.mandatory_zero_repository:
                self.mandatory_zero_final_results[result] = results[result]
            elif 'key_exchange_score' in result:
                self.certificate_results[result] = results[result]
            elif 'cipher_strength_score' in result:
                self.cipher_suites_results[result] = results[result]
            else:  # All other vulnerabilities
                self.vulnerabilities_results[result] = results[result]
        pass

    def compute_protocol_score(self):
        protocols_scores = []
        for result in self.cipher_suites_results:
            if 'protocol_score' in result:
                protocols_scores.append(self.cipher_suites_results[result])
        return (min(protocols_scores)+max(protocols_scores)) / 2

    def compute_key_exchange_score(self):
        if len(self.certificate_results) > 0:
            return self.certificate_results['key_exchange_score']
        else:
            return "0"

    def compute_cipher_strength_score(self):
        cipher_strength_scores = []
        for result in self.cipher_suites_results:
            if 'cipher_strength_score' in result:
                cipher_strength_scores.append(self.cipher_suites_results[result])
        return (min(cipher_strength_scores) + max(cipher_strength_scores)) / 2

    def get_final_results(self):

        # Server should get a zero score?
        if len(self.mandatory_zero_final_results) > 0:
            description = ""
            for key in self.mandatory_zero_final_results:
                description += key + ". "
            return self.final_grades_repository["<20"] + "{} [0]".format(description)

        # Any grade's cap?
        elif True:
            pass

        # So, compute the server's final score!
        else:
            key_exchange_score = self.compute_key_exchange_score()
            cipher_strength_score = self.compute_cipher_strength_score()
            protocol_score = self.compute_protocol_score()

            final_score = (key_exchange_score * GradesEnum.KEY_FACTOR.value) + \
                          (cipher_strength_score * GradesEnum.CIPHER_FACTOR.value) + \
                          (protocol_score * GradesEnum.PROTOCOL_FACTOR.value)

            if final_score >= 80:
                return self.final_grades_repository[">=80"] + " [{}]".format(final_score)
            elif final_score >= 65:
                return self.final_grades_repository[">=65"] + " [{}]".format(final_score)
            elif final_score >= 50:
                return self.final_grades_repository[">=50"] + " [{}]".format(final_score)
            elif final_score >= 35:
                return self.final_grades_repository[">=35"] + " [{}]".format(final_score)
            elif final_score >= 20:
                return self.final_grades_repository[">=20"] + " [{}]".format(final_score)
            else:  # final_score < 20
                return self.final_grades_repository["<20"] + " [{}]".format(final_score)
