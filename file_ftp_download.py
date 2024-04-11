import os, sys, subprocess, hashlib
from pathlib import Path
from datetime import datetime, timedelta
from logging import handlers, Formatter,getLogger, INFO
import cx_Oracle
import pickle
import file_process_init as fp
import time

class Ftp_File_Download:
# =============================================================================
# Initialize variables
# =============================================================================
    def __init__(self, component_name):
        
        if len(sys.argv) > 1:
            self.arg1 = sys.argv[1]
        else:
            self.arg1 = 'LOCAL'
            
        self.init_var = fp.file_data_initialize(component_name, self.arg1)
        self.logger = None
        self.db_config_row = None
        self.tracks_records = []
        
# =============================================================================
# Function for printing       
# =============================================================================
    def xprint(self, *args, **kwargs):
        if self.init_var.print_flag == 'Y':
            print("".join(map(str,args)))
            
# =============================================================================
# Set up logging attributes   
# =============================================================================
    def set_logger(self):
        self.logfile = "".join([str(Path(self.init_var.log_file)),"_",datetime.strftime(datetime.now(), "%Y%m%d"),".log"])
    
        self.logger = getLogger(__name__)
        self.logger.setLevel(level = INFO)

        if (self.logger.hasHandlers()):
            self.logger.handlers.clear()
            
        # Add logger handlers only if no handlers present
        if not self.logger.hasHandlers():
            self.log_format = "%(asctime)s - %(levelname)s - %(message)s"
            self.log_handler = handlers.TimedRotatingFileHandler(self.logfile, when="midnight", interval=1)
            self.formatter = Formatter(self.log_format)
            self.log_handler.setFormatter(self.formatter)
            # add a date suffix
            self.log_handler.suffix = "%Y%m%d"
            # add handler to logger
            self.logger.addHandler(self.log_handler)
        
        os.chmod(self.logfile,0o777)

# =============================================================================
# Function to log information in database
# =============================================================================
    def db_log_insert(self, filename, component_type="", status="", log_type="", log_details="", CREATED_BY="SYSTEM", log_ftp_id=""):
        global db_user, db_password, dsnstr

        # Create a file hash
        file_name_hash = hashlib.sha1(filename.encode()).hexdigest()
        
        # Create a log entry in database
        dsnstr = cx_Oracle.makedsn(self.init_var.db_host, self.init_var.db_port, self.init_var.db_sid)
        oracle_db = cx_Oracle.connect(user=self.init_var.db_user, password=self.init_var.db_password, dsn=self.init_var.dsnstr)
        db_cursor = oracle_db.cursor()

        # Get the DB sequence
        db_cursor.execute('select {db_user}.seq_file_status_log_key.nextval from dual'.format(db_user = self.init_var.db_user))
        db_seq = db_cursor.fetchone()

        # Run the Insert statement in log table
        db_statement = 'INSERT INTO {db_schema}.TBT_FP_STATUS_LOG (STATUS_LOG_KEY, FILE_NAME_HASH, COMPONENT_TYPE, STATUS, \
                            LOG_TYPE, LOG_DETAILS, CREATED_DATE, CREATED_BY, FTP_UNIQUE_ID) \
                            VALUES (:2, :3, :4, :5, :6, :7, :8, :9, :10)'.format(db_schema=self.init_var.db_user)
        db_cursor.execute(db_statement, (db_seq[0],file_name_hash, component_type, status, log_type, log_details, \
                                         datetime.now(), CREATED_BY, log_ftp_id))
        oracle_db.commit()
        db_cursor.close()
        oracle_db.close()
    
# =============================================================================
# Function to define current time
# =============================================================================
    def define_curr_time(self, now):
        hour = str(now.hour)
        minute = str(now.minute)
        hour_minute = "".join([hour.rjust(2,'0'), ":", minute.rjust(2, '0')])
        
        return hour_minute
        
# =============================================================================
# Main Program
# =============================================================================
if __name__ == "__main__":
    try:
        # Initialize variables
        fp_init = Ftp_File_Download('FTP_FILE_DOWNLOAD')
        
        fp_init.xprint("Program started")
        # set Logger
        fp_init.set_logger()
        
        fp_init.logger.info('Execution start ' + '\n')
        
        # Delete Stop file at start if present
        if os.path.exists(fp_init.init_var.stop_file_path):
            os.remove(fp_init.init_var.stop_file_path)
            
        # Set ENV variables
        today = datetime.strftime(datetime.now(), '%Y%m%d')
        
        fp_init.logger.info("################################ SCRIPT START ################################ ")
        
        # Set DB parameters to run SQL query
        dsnstr = cx_Oracle.makedsn(fp_init.init_var.db_host, fp_init.init_var.db_port, fp_init.init_var.db_sid)
        oracle_db = cx_Oracle.connect(user = fp_init.init_var.db_user, password = fp_init.init_var.db_password, dsn = dsnstr)
        db_cursor = oracle_db.cursor()
        fp_init.logger.info("Connected to DB")
      
        # Update current execution time
        resume_time = fp_init.define_curr_time(datetime.now())
        latest_time = fp_init.define_curr_time(datetime.now())
               
        # Continous PULL if stop.txt not detected
        while not os.path.exists(fp_init.init_var.stop_file_path):
               
            # Retrieve total number of File Unique IDs to Pull at specified timing
            sql_command = '''
                            SELECT FTP_UNIQUE_ID
                            FROM {param1}
                            WHERE ALERT_TIME BETWEEN '{param2}' AND '{param3}' AND FILE_STATUS = 'ACTIVE' AND FTP_TYPE = 'PULL'
                            '''.format(param1=fp_init.init_var.ftp_config_table, param2=resume_time, param3=latest_time)
            db_cursor.execute(sql_command)
            count_record = db_cursor.fetchall()                
            
            print("####################### DETECTING JOBS #######################")
                  
            # Perform Pull files
            count_record_length = len(count_record)
            
            for i in range(count_record_length):
                
                sql_command ='''
                                SELECT FTP_SPID, FTP_PORT, FTP_SERVER_NAME, SSL_CERT, SSL_KEY, \
                                FTP_SERVER_PATH, FTP_LOCAL_PATH, FILE_NAME_REGEX, FTP_TYPE \
                                FROM {param1} \
                                WHERE FTP_UNIQUE_ID = {param2}
                                '''.format(param1=fp_init.init_var.ftp_config_table, param2=count_record[i][0])
                                
                db_cursor.execute(sql_command)
                query_result = db_cursor.fetchall()
                fp_init.logger.info("Performed sql query search")
                
                # Assign variables from sql query result
                ftp_spid = query_result[0][0]
                ftp_port = query_result[0][1]
                ftp_server_name = query_result[0][2]
                ssl_cert = query_result[0][3]
                ssl_key = query_result[0][4]
                data_store = query_result[0][5]
                local_store = query_result[0][6]
                file_name_regex = query_result[0][7]
                ftp_type = query_result[0][8]
                fp_init.logger.info("Assign variables from sql query result")
                
                login = "".join(["lftp -u ", ftp_spid, ",null -p ", ftp_port, " ", ftp_server_name])
                set_ssl_cert = "".join(["set ssl:cert-file ", ssl_cert])
                set_ssl_key = "".join(["set ssl:key-file ", ssl_key])
                data_path = data_store
                landing_path = local_store
                filename = file_name_regex
                fp_init.logger.info("Create FTP command details")
                
                # Determine PULL files
                if ftp_type == "PULL":
                    fp_init.logger.info("Performing pull {param1}".format(param1 = file_name_regex))
                    
                    # Get file from Server
                    ftp_command = '''
                                    {param1}
                                    {param2}
                                    {param3}
                                    cd {param4}
                                    lcd {param5}
                                    mget {param6}
                                    '''.format(param1=login, param2=set_ssl_cert, param3=set_ssl_key, param4=data_path, param5=landing_path, param6=filename)
                    commands = ftp_command.encode()
                    process = subprocess.Popen('/bin/bash', stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    out, error = process.communicate(commands)
                    fp_init.logger.info("Checking if {param1} is pulled from server".format(param1 = filename))
     
                    # Check existence of file
                    if (out != b''):
                        
                        # Convert byte to string
                        item_list = out.decode("utf-8")
                        
                        # Retrieve filename from list
                        filename = item_list.split().pop()
                        
                        print("Current Filename: ", filename)
                        
                        fp_init.logger.info("{param1} exist in {param2}".format(param1 = filename, param2 = data_path)) 
     
                        # Change directory to where files are downloaded
                        os.chdir(landing_path)
                        fp_init.logger.info("Change directory to {param1}, check for file existence".format(param1 = landing_path))
                        
                        # Check if file is downloaded to FTP folder
                        if os.path.isfile(filename):
                            fp_init.logger.info("File - {param1} downloaded successfully to {param2}".format(param1 = filename, param2 = landing_path))
                            log_details = "File - {param1} downloaded successfully to {param2}".format(param1 = filename, param2 = landing_path)
                            status = "Success"
                            log_type = "INFO"
                        
                            # Give permission to files download
                            os.chmod(filename, 0o777)
                            fp_init.logger.info("Grant permission to {param1}".format(param1 = filename))
                            
                        else:
                            fp_init.logger.error("File - {param1} not downloaded successfully to {param2}".format(param1 = filename, param2 = landing_path))
                            log_details = "File - {param1} not downloaded successfully to {param2}".format(param1 = filename, param2 = landing_path)
                            status = "Fail"
                            log_type = "Error"
                        
                    else:
                        fp_init.logger.error("File - {param1} not found in {param2}".format(param1 = filename, param2 = data_path))
                        log_details = "File - {param1} not found in {param2}".format(param1 = filename, param2 = data_path)
                        status = "Fail"
                        log_type = "ERROR"
                        
                else:
                    fp_init.logger.error("{param1} FTP type not recognized".format(param1 = ftp_type))
                    log_details = "{param1} FTP type not recognized".format(param1 = ftp_type)
                    status = "Fail"
                    log_type = "ERROR"
    
                # Define DB variables
                component_type = "FTP_{param1}".format(param1 = ftp_type)
                log_ftp_id = count_record[i][0]

                # Insert log into DB
                fp_init.db_log_insert(filename=filename, component_type=component_type, status=status, log_type=log_type, log_details=log_details)
                
        else:
            # Exit Statement upon detection of stop.txt file
            print("Stop file is invokved at {param1}".format(param1 = fp_init.init_var.stop_file_path))
            fp_init.logger.info("Stop file is invoked at {param1}".format(param1 = fp_init.init_var.stop_file_path))
            
        # Update current execution time
        resume_time = latest_time
        latest_time = fp_init.define_curr_time(datetime.now())
                
        # Exit DB connection
        db_cursor.close()
        oracle_db.close()
        
        fp_init.logger.info("################################ SCRIPT END ################################ ")
        
    except Exception as e:
        print("Exception occured while processing: {err}".format(err = str(e)))
        fp_init.logger.error("Exception occurred while processing: {err}".format(err = str(e)), exc_info=True)
        
        
        
        
        
        
        
        
        
        