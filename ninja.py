# Description: Main file for the Ninja project
import queue
import time
import threading
import logging
from modules.certfeed import Certfeed
from modules.ruleset import YaraRules, Typosquatting

domains_queue = queue.Queue()
domains_dict = {}
cert_engine = Certfeed(domains_queue, domains_dict)
yara_engine = YaraRules()
typosquatting_engine = Typosquatting()


def queue_worker():
    while True:
        while domains_queue.empty():
            time.sleep(1)
        current_domain = domains_queue.get()
        if current_domain is None:
            continue
        yara_matches = yara_engine.match(current_domain)
        typosquatting_matches = typosquatting_engine.check_domain_distance(current_domain, max_distance=1)
        if len(yara_matches) > 0:
            print("Yara match")
            print("Matched domain:", current_domain)
            print("Yara Rules:", yara_matches)
        elif typosquatting_matches is not None:
            print("Typosquatting match")
            print("Possible Typosquatted:", current_domain)
            print("Monitored domain:", typosquatting_matches)
        else:
            domains_dict.pop(current_domain, None)
        domains_queue.task_done()


for _ in range(50):
    t = threading.Thread(target=queue_worker)
    t.daemon = True
    t.start()
    

domains_queue.join()
while True:
    print("Size of Queue:", domains_queue.qsize())
    print("Size of Dict:", len(domains_dict))
    time.sleep(60*10)

