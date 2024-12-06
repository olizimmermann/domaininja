# Description: Main file for the Ninja project
import queue
import time
import threading
import logging
import os
import dotenv
from modules.certfeed import Certfeed
from modules.ruleset import YaraRules, Typosquatting, OnPoint
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
onpoint = OnPoint()
typosquatting_engine = Typosquatting()

yara_rule_enabled = False
typosquatting_enabled = True
onpoint_enabled = True

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
            logger.info("No subdomains left")
            time.sleep(30)

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
        
        if yara_rule_enabled:
            yara_matches = yara_engine.match(current_domain)
        else:
            yara_matches = []

        if onpoint_enabled:
            onpoint_matches = onpoint.match(current_domain)
        else:
            onpoint_matches = None

        if typosquatting_enabled:
            typosquatting_matches = typosquatting_engine.check_domain_distance(current_domain, max_distance=1, dynamic_max_distance=True)
        else:
            typosquatting_matches = None
        finding = False
        if len(yara_matches) > 0:
            logger.info("Yara match")
            logger.info(f"Matched domain: {current_domain}")
            logger.info(f"Yara Rules: {yara_matches}")
            # with lock:
            #     db.update_domain(current_domain, yara_matches[0])
            finding = True
        elif typosquatting_matches is not None:
            logger.info("Typosquatting match")
            logger.info(f"Possible Typosquatted: {current_domain}")
            with lock:
                db.update_domain(current_domain, typosquatting_matches)
            logger.info(f"Monitored domain: {typosquatting_matches}")
            finding = True
        elif onpoint_matches is not None:
            logger.info("OnPoint match")
            logger.info(f"Matched domain: {current_domain}")
            with lock:
                db.update_domain(current_domain, onpoint_matches)
            logger.info(f"Monitored domain: {onpoint_matches}")
            finding = True
        if finding:
            try:
                sub_domains_list = cert_engine.get_sub_domains(domains_dict[current_domain])
            except KeyError:
                sub_domains_list = []
            for sub_domain in sub_domains_list:
                if not sub_domain == '*':
                    sub_domains.append(sub_domain)
        
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

# sub_domains_cleaner = threading.Thread(target=sub_domain_cleaner)
# sub_domains_cleaner.daemon = True
# sub_domains_cleaner.start()

# domains_queue.join()
while True:
    logger.info("Size of Queue: " + str(domains_queue.qsize()))
    logger.info("Size of Dict " + str(len(domains_dict)))
    time.sleep(60*10)

