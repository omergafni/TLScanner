import json

from utils.server_rates import GradesEnum, MandatoryZeroFinalGrade, FinalGradeCaps


class ResultsParser(object):
    """
    This class responsibility is to parse the final json results getting by all the scan commands.
    The class final outcome is the scan summarize and the final server's grade.
    """
    final_grades_repository = {"80": [GradesEnum.GradeDescription.A_PLUS.value, 'A'],  # TODO: A+/-
                               "65": [GradesEnum.GradeDescription.B.value, 'B'],
                               "50": [GradesEnum.GradeDescription.C.value, 'C'],
                               "35": [GradesEnum.GradeDescription.D.value, 'D'],
                               "20": [GradesEnum.GradeDescription.E.value, 'E'],
                               "0": [GradesEnum.GradeDescription.F.value, 'F']}

    """
    Repositories MUST hold all the corresponding enums.
    """
    final_grade_caps_repository = {FinalGradeCaps.USING_SHA1_CERTIFICATE.value,
                                   FinalGradeCaps.POODLE_VULNERABILITY.value,
                                   FinalGradeCaps.TLS_FALLBACK_SCSV_NOT_SUPPORTED.value,
                                   FinalGradeCaps.SSL3_SUPPORTED.value}

    mandatory_zero_repository = [MandatoryZeroFinalGrade.CERTIFICATE_NOT_TRUSTED.value,
                                 MandatoryZeroFinalGrade.CERTIFICATE_NOT_YET_VALID.value,
                                 MandatoryZeroFinalGrade.CERTIFICATE_EXPIRED.value,
                                 MandatoryZeroFinalGrade.DOMAIN_MISS_MATCH.value,
                                 MandatoryZeroFinalGrade.SSL20_SUPPORTED.value,
                                 MandatoryZeroFinalGrade.OPENSSL_CCS_INJECTION_VULNERABILITY.value,
                                 MandatoryZeroFinalGrade.DROWN_VULNERABILITY.value,
                                 MandatoryZeroFinalGrade.INSECURE_RENEGOTIATION.value,
                                 MandatoryZeroFinalGrade.HEARTBLEED_VULNERABILITY.value]
                                 # MandatoryZeroFinalGrade.KEY_UNDER_1024.value]

    def __init__(self):
        self.certificate_results = {}
        self.protocols_cipher_suites_results = {}
        self.vulnerabilities_results = {}
        self.mandatory_zero_final_results = {}
        self.final_grade_caps_results = {}

    def sort_and_parse_json_results(self, json_results):

        results = {}
        for json_result in json_results:
            results.update(json.loads(json_result))

        for result in results:
            if result in self.mandatory_zero_repository:
                self.mandatory_zero_final_results[result] = results[result]
            elif result in self.final_grade_caps_repository:
                self.final_grade_caps_results[result] = results[result]
            elif 'certificate' in result:
                self.certificate_results[result] = results[result]
            elif 'protocol' in result:
                self.protocols_cipher_suites_results[result] = results[result]
            else:  # All other vulnerabilities
                self.vulnerabilities_results[result] = results[result]

        pass

    def compute_protocol_score(self):
        protocols_scores = []
        for result in self.protocols_cipher_suites_results:
            if 'protocol_score' in result:
                protocols_scores.append(self.protocols_cipher_suites_results[result])
        return (min(protocols_scores)+max(protocols_scores)) / 2

    def compute_key_exchange_score(self):
        if len(self.certificate_results) > 0:
            return self.certificate_results['certificate_key_exchange_score']
        else:
            raise ValueError('Should never happen')

    def compute_cipher_strength_score(self):
        cipher_strength_scores = []
        for result in self.protocols_cipher_suites_results:
            if 'cipher_strength_score' in result:
                cipher_strength_scores.append(self.protocols_cipher_suites_results[result])
        return (min(cipher_strength_scores) + max(cipher_strength_scores)) / 2

    def find_lowest_cap_from_results(self):

        caps_results = self.final_grade_caps_results
        caps = {'cap to A-': 4, 'cap to B': 3, 'cap to C': 2, 'cap to D': 1, 'cap to E': 0}
        numbers_to_cap = {4: 'A-', 3: 'B', 2: 'C', 1: 'D', 0: 'E'}
        minimum_cap = 4
        for cap in caps_results:
            if caps[caps_results[cap]] < minimum_cap:
                minimum_cap = caps[caps_results[cap]]

        return numbers_to_cap[minimum_cap]

    @staticmethod
    def apply_cap_on_score(score, cap):

        caps_values = {'A-': GradesEnum.GradeValue.A.value, 'B': GradesEnum.GradeValue.B.value,
                       'C': GradesEnum.GradeValue.C.value, 'D': GradesEnum.GradeValue.D.value,
                       'E': GradesEnum.GradeValue.E.value}

        max_score = caps_values[cap]

        if max_score <= score:
            return max_score
        else:
            return score

    def get_final_results(self):

        description = ""
        # Server should get a zero score?
        if len(self.mandatory_zero_final_results) > 0:
            for key in self.mandatory_zero_final_results:
                description += key + ". "
            return self.final_grades_repository["0"][0] + "{}[0]".format(description)

        # If not, compute the server's final score!
        else:
            key_exchange_score = self.compute_key_exchange_score()
            cipher_strength_score = self.compute_cipher_strength_score()
            protocol_score = self.compute_protocol_score()

            final_score = (key_exchange_score * GradesEnum.GradeFactor.KEY_FACTOR.value) + \
                          (cipher_strength_score * GradesEnum.GradeFactor.CIPHER_FACTOR.value) + \
                          (protocol_score * GradesEnum.GradeFactor.PROTOCOL_FACTOR.value)

            # Any grade's cap?
            if len(self.final_grade_caps_results) > 0:
                final_score = self.apply_cap_on_score(final_score, self.find_lowest_cap_from_results())
                for cap_description in self.final_grade_caps_results:
                    description += cap_description + ". "

            # Return the server's final grade:
            if final_score >= 80:
                return self.final_grades_repository["80"][0] + "{}[{}]".format(description, final_score)
            elif final_score >= 65:
                return self.final_grades_repository["65"][0] + "{}[{}]".format(description, final_score)
            elif final_score >= 50:
                return self.final_grades_repository["50"][0] + "{}[{}]".format(description, final_score)
            elif final_score >= 35:
                return self.final_grades_repository["35"][0] + "{}[{}]".format(description, final_score)
            elif final_score >= 20:
                return self.final_grades_repository["20"][0] + "{}[{}]".format(description, final_score)
            else:  # final_score < 20
                return self.final_grades_repository["0"][0] + "{}[{}]".format(description, final_score)
