import json


class ResultsParser(object):
    """
    This class responsibility is to parse the final json results getting by all the scan commands.
    The class final outcome is the scan summarize and the final server's grade.
    """
    def __init__(self):
        self.certificate_results = {}
        self.cipher_suites_results = {}
        self.vulnerabilities_results = {}

    def sort_and_parse_json_results(self, json_results):
        for result in json_results:
            if 'key_exchange_score' in result:
                self.certificate_results.update(json.loads(result))
            elif 'cipher_strength_score' in result:
                self.cipher_suites_results.update(json.loads(result))
            else:  # All other vulnerabilities
                self.vulnerabilities_results.update(json.loads(result))

    def compute_protocol_score(self):
        protocols_scores = []
        for result in self.cipher_suites_results:
            if 'protocol_score' in result:
                protocols_scores.append(self.cipher_suites_results[result])
        return (min(protocols_scores)+max(protocols_scores)) / 2

    def compute_key_exchange_score(self):
        return self.certificate_results['key_exchange_score']

    def compute_cipher_strength_score(self):
        cipher_strength_scores = []
        for result in self.cipher_suites_results:
            if 'cipher_strength_score' in result:
                cipher_strength_scores.append(self.cipher_suites_results[result])
        return (min(cipher_strength_scores) + max(cipher_strength_scores)) / 2

    def get_final_results(self):
        key_exchange_score = self.certificate_results['key_exchange_score']


