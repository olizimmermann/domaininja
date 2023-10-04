# Description: Main file for the Ninja project
import queue
import time
from modules.certfeed import Certfeed
from modules.ruleset import YaraRules

domains_queue = queue.Queue()
cert_engine = Certfeed(domains_queue)
yara_engine = YaraRules()

# while domains_queue is not empty check for matches
while True:
    while not domains_queue.empty():
        print("Queue length: " + str(domains_queue.qsize()))
        current_domain = domains_queue.get()
        matches = yara_engine.match(current_domain)
        if len(matches) > 0:
            print(current_domain)
            print(matches)

    time.sleep(5)


