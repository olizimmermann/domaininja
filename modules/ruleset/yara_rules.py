import yara
import os

class YaraRules:
    
    def __init__(self):
        self.rules = None
        self.rule_files = []
        rules_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "yara_rules")
        self.find_rules(rules_path)
        self.load_all_rules()
        
    def find_rules(self, folder_path):
        if os.path.isdir(folder_path):
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file.endswith(".yara"):
                        self.rule_files.append(os.path.join(root, file))
            
    def load_all_rules(self):
        ruleset = {}
        for rule_file in self.rule_files:
            basename = os.path.basename(rule_file)
            ruleset[basename] = rule_file
        self.rules = yara.compile(filepaths=ruleset)
            
    def match(self, domain, **kwargs):
        if self.rules is not None:
            return self.rules.match(data=domain, **kwargs)
        else:
            return None