import os
import logging

class Typosquatting:
    
    def __init__(self, domains_path: str = os.path.join(os.path.dirname(os.path.realpath(__file__)), "typosquatting" ,"mb.txt")):
        self.domains = []
        logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO, filename='ninja.log')
        self.logger = logging.getLogger(__name__)
        self.logger.info("Starting Typosquatting")
        self.load_domains(domains_path)
    
    def load_domains(self, domains_path: str):
        if not os.path.isfile(domains_path):
            self.logger.warning("Domains file not found: " + domains_path)
        with open(domains_path, "r") as f:
            for line in f:
                self.domains.append(line.strip())
    
    def check_domain_distance(self, given_domain, original_domains: list = None, max_distance: int = 1, dynamic_max_distance: bool = False):
        if original_domains is None:
            original_domains = self.domains
        if len(given_domain.split(".")) > 2: # ignore subdomains
            given_domain = ".".join(given_domain.split(".")[-2:])
        if len(given_domain) < 5: # ignore short domains
            return None
        if dynamic_max_distance:
            max_distance = len(given_domain) // 8
        for domain in original_domains:
            distance = self.levenshtein_distance(domain, given_domain)
            if distance <= max_distance and distance > 0:
                self.logger.info("Found typosquatting domain: " + domain + " (distance: " + str(distance) + ")")
                self.logger.info("Given domain: " + given_domain)
                return domain
        return None
        
    def levenshtein_distance(self, domain: str, given_domain: str): # https://en.wikibooks.org/wiki/Algorithm_Implementation/Strings/Levenshtein_distance#Python
        if len(domain) > len(given_domain):
            domain, given_domain = given_domain, domain
        distances = range(len(domain) + 1)
        for index2, char2 in enumerate(given_domain):
            new_distances = [index2 + 1]
            for index1, char1 in enumerate(domain):
                if char1 == char2:
                    new_distances.append(distances[index1])
                else:
                    new_distances.append(1 + min((distances[index1],
                                                 distances[index1 + 1],
                                                 new_distances[-1])))
            distances = new_distances
        return distances[-1]