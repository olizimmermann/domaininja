import pymysql
import pymysql.cursors
import os
import logging

class Database:
    
    def __init__(self, host: str, port: int, username: str, password: str, database: str):
        self.connection = None
        logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO, filename='ninja.log')
        self.logger = logging.getLogger(__name__)
        self.logger.info("Starting Database module")
        self.connect(host, port, username, password, database)
        pymysql.threadsafety = 2
        if self.connection is not None:
            self.logger.info("Connected to database")
            self.init_database()
        
    def connect(self, host: str, port: int, username: str, password: str, database: str):
        """ Connects to MySQL database """
        try:
            self.connection = pymysql.connect(host=host, port=port, user=username, passwd=password, db=database, charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)
        except Exception as e:
            self.logger.error("Error connecting to database: " + str(e))
            return False
        return True
    
    def is_connected(self):
        """ Checks if the database is connected """
        if self.connection is None:
            return False
        return True
    
    def check_connection(self):
        """ Checks the database connection and reconnects if necessary """
        if not self.is_connected():
            self.connect()
    
    def init_database(self):
        """ Creates the tables if they do not exist """
        # use sql file to create tables
        # use sql/init_db.sql
        
        if os.path.isfile("sql/init_db.sql"):
            with open("sql/init_db.sql", "r") as f:
                sql_file = f.read()
                for sql in sql_file.split(";"):
                    if sql == "" or sql == "\n" or sql.strip() == "":
                        continue
                    with self.connection.cursor() as cursor:
                        cursor.execute(sql)
                        self.connection.commit()
                self.logger.info("Created tables")
        else:
            self.logger.warning("init_db.sql does not exist")
            
    def get_domain(self, domain, original_domain):
        """ Gets the domain from the database """
        self.check_connection()
        sql = "SELECT * FROM domains WHERE domain = %s AND original_domain = %s"
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (domain, original_domain,))
            return cursor.fetchone()
    
    def update_domain(self, domain, original_domain):
        """ Updates the domain in the database """
        self.check_connection()
        domain_entry = self.get_domain(domain, original_domain)
        if domain_entry is None:
            self.insert_domain(domain, original_domain)
            return
        times_seen = domain_entry["times_seen"] + 1
        sql = "UPDATE domains SET times_seen = %s WHERE domain = %s AND original_domain = %s"
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (times_seen, domain, original_domain))
            self.connection.commit()
        
    def insert_domain(self, domain, original_domain):
        """ Inserts the domain into the database """
        self.check_connection()
        sql = "INSERT INTO domains (domain, original_domain, times_seen) VALUES (%s, %s, %s)"
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (domain, original_domain, 1))
            self.connection.commit()
        
    def get_subdomain(self, sub_domain):
        """ Gets the subdomain from the database """
        self.check_connection()
        sql = "SELECT * FROM subdomains WHERE subdomain = %s"
        with self.connection.cursor() as cursor:
            # as dictionary
            cursor.execute(sql, (sub_domain,))
            return cursor.fetchone()
            
    def update_subdomain(self, sub_domain):
        """ Updates the subdomain in the database """
        self.check_connection()
        sub_domain_entry = self.get_subdomain(sub_domain)
        if sub_domain_entry is None:
            self.insert_subdomain(sub_domain)
            return
        times_seen = sub_domain_entry["times_seen"] + 1
        sql = "UPDATE subdomains SET times_seen = %s WHERE subdomain = %s"
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (times_seen, sub_domain))
            self.connection.commit()
            
    def insert_subdomain(self, sub_domain):
        """ Inserts the subdomain into the database """
        self.check_connection()
        sql = "INSERT INTO subdomains (subdomain, times_seen) VALUES (%s, %s)"
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (sub_domain, 1))
            self.connection.commit()
        
    def clean_subdomains(self, last_seen_minutes, min_times_seen=3):
        """ Cleans the subdomains from the database """
        self.check_connection()
        sql = "DELETE FROM subdomains WHERE times_seen < %s AND last_seen < DATE_SUB(NOW(), INTERVAL %s MINUTE)"
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (min_times_seen, last_seen_minutes))
            self.connection.commit()