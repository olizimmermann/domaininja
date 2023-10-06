import pymysql
import pymysql.cursors
import os

class Database:
    
    def __init__(self, host: str, port: int, username: str, password: str, database: str):
        self.connection = None
        self.connect(host, port, username, password, database)
        if self.connection is not None:
            print("Connected to database")
            self.init_database()
        
    def connect(self, host: str, port: int, username: str, password: str, database: str):
        """ Connects to MySQL database """
        try:
            self.connection = pymysql.connect(host=host, port=port, user=username, passwd=password, db=database, charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)
        except Exception as e:
            print("Error connecting to database: " + str(e))
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
                print("Created tables")
        else:
            print("init_db.sql does not exist")
            
    def get_domain(self, domain):
        """ Gets the domain from the database """
        self.check_connection()
        sql = "SELECT * FROM domains WHERE domain = %s"
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (domain,))
            return cursor.fetchone()
    
    def update_domain(self, domain):
        """ Updates the domain in the database """
        self.check_connection()
        domain_entry = self.get_domain(domain)
        if domain_entry is None:
            self.insert_domain(domain)
            return
        times_seen = domain_entry["times_seen"] + 1
        sql = "UPDATE domains SET times_seen = %s WHERE domain = %s"
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (times_seen, domain))
            self.connection.commit()

    def insert_domain(self, domain):
        """ Inserts the domain into the database """
        self.check_connection()
        sql = "INSERT INTO domains (domain, times_seen) VALUES (%s, %s)"
        with self.connection.cursor() as cursor:
            cursor.execute(sql, (domain, 1))
            self.connection.commit()
        
        
        
        
        