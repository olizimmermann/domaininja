# Description: Main file for the Ninja project
import queue
import time
import threading
import logging
import os
import dotenv
from modules.certfeed import Certfeed
from modules.ruleset import YaraRules, Typosquatting
from modules.db import Database

dotenv.load_dotenv(".env")

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO, filename='ninja.log')
logger = logging.getLogger(__name__)

logger.info("Starting Ninja")

db = Database(host=DB_HOST, port=int(DB_PORT), username=DB_USER, password=DB_PASS, database="ninja")

lock = threading.Lock()
domains_queue = queue.Queue()
domains_dict = {}
cert_engine = Certfeed(domains_queue, domains_dict)
yara_engine = YaraRules()
typosquatting_engine = Typosquatting()

sub_domains = []

def sub_domain_worker():
    while True:
        tmp_sub_domains = sub_domains.copy()
        sub_domains.clear()
        if len(tmp_sub_domains) > 0:
            logger.info("Found " + str(len(tmp_sub_domains)) + " subdomains")
            for sub_domain in tmp_sub_domains:
                with lock:
                    db.update_subdomain(sub_domain)
        else:
            time.sleep(10)
            logger.info("No subdomains left")

def sub_domain_cleaner():
    while True:
        with lock:
            db.clean_subdomains(last_seen_minutes=30, min_times_seen=3)
        logger.info("Cleaned subdomains")
        time.sleep(60*10)             
        

def queue_worker():
    while True:
        while domains_queue.empty():
            time.sleep(1)
        current_domain = domains_queue.get()
        if current_domain is None:
            continue
        try:
            sub_domains_list = cert_engine.get_sub_domains(domains_dict[current_domain])
        except KeyError:
            sub_domains_list = []
        for sub_domain in sub_domains_list:
            if not sub_domain == '*':
                sub_domains.append(sub_domain)
        yara_matches = yara_engine.match(current_domain)
        typosquatting_matches = typosquatting_engine.check_domain_distance(current_domain, max_distance=1, dynamic_max_distance=True)
        if len(yara_matches) > 0:
            logger.info("Yara match")
            logger.info(f"Matched domain: {current_domain}")
            logger.info(f"Yara Rules: {yara_matches}")
        elif typosquatting_matches is not None:
            logger.info("Typosquatting match")
            logger.info(f"Possible Typosquatted: {current_domain}")
            with lock:
                db.update_domain(current_domain)
            logger.info(f"Monitored domain: {typosquatting_matches}")
        else:
            domains_dict.pop(current_domain, None)
        domains_queue.task_done()


for _ in range(100):
    t = threading.Thread(target=queue_worker) # docker container to spin up?
    t.daemon = True
    t.start()
    
sub_domains_worker = threading.Thread(target=sub_domain_worker)
sub_domains_worker.daemon = True
sub_domains_worker.start()

sub_domains_cleaner = threading.Thread(target=sub_domain_cleaner)
sub_domains_cleaner.daemon = True
sub_domains_cleaner.start()

# domains_queue.join()
while True:
    logger.info("Size of Queue: " + str(domains_queue.qsize()))
    logger.info("Size of Dict " + str(len(domains_dict)))
    time.sleep(60*10)

