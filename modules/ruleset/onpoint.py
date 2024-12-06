import yara
import os
import logging

class OnPoint:
    
    def __init__(self):
        logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO, filename='ninja.log')
        self.logger = logging.getLogger(__name__)
        self.logger.info("Starting OnPoint")
        self.domain_files = []
        self.domains = []
        rules_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "onpoint")
        self.find_domain_lists(rules_path)
        self.load_all_domains()
        
    def find_domain_lists(self, folder_path):
        if os.path.isdir(folder_path):
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file.endswith(".txt"):
                        logging.info("Found domain list: " + file)
                        self.domain_files.append(os.path.join(root, file))
            
    def load_all_domains(self):
        for domain_file in self.domain_files:
            with open(domain_file, 'r') as f:
                for line in f:
                    self.domains.append(line.strip())
        logging.info("Loaded " + str(len(self.domains)) + " domains")
            
    def match(self, domain, **kwargs):
        for d in self.domains:
            if d in domain:
                return d
        else:
            return None