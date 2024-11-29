import argparse
from pathlib import Path

ROOT = Path(__file__).parent.parent

import sys
sys.path.append(str(ROOT/"src"))

import platform
from datetime import datetime
from mlcbase import Logger, MySQLAPI, SQLiteAPI


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--python_version", required=True)
    parser.add_argument("--charset", default="utf8")

    args = parser.parse_args()
    return args


def run():
    args = parse_args()
    table_name = f"user_{platform.system()}_{''.join(args.python_version.split('.'))}"

    logger = Logger()
    logger.init_logger()

    ## test MySQL
    logger.info("Testing MySQL...")
    db_api = MySQLAPI(host=args.host, 
                      port=int(args.port), 
                      user=args.user, 
                      database=args.database, 
                      password=args.password, 
                      charset=args.charset, 
                      logger=logger)
    
    # create table
    status = db_api.create_table(
        table_name=table_name, 
        table_config=[dict(name="id", dtype="int", not_null=True, primary_key=True, auto_increment=True),
                      dict(name="name", dtype="varchar(255)", not_null=True),
                      dict(name="age", dtype="integer", not_null=True),
                      dict(name="gender", dtype="varchar(255)", default="Unknown", not_null=True),
                      dict(name="add_date", dtype="date")]
    )
    if not status:
        raise RuntimeError("MySQL test failed.")
    
    # get tables
    if db_api.get_tables(show=True) is None:
        raise RuntimeError("MySQL test failed.")
    
    # get fields
    if db_api.get_fields(table_name=table_name, show=True) is None:
        raise RuntimeError("MySQL test failed.")
    
    # insert data
    user_data = [dict(name="Weiming Chen", age=27, gender="male", add_date=datetime.now().strftime("%Y-%m-%d")),
                 dict(name="John", age=16, add_date=datetime.now().strftime("%Y-%m-%d")),
                 dict(name="David", age=45, add_date=datetime.now().strftime("%Y-%m-%d")),
                 dict(name="Peter", age=35)]
    for data in user_data:
        if not db_api.insert_data(table_name=table_name, data=data):
            raise RuntimeError("MySQL test failed.")
    
    # search data
    logger.info("Case 1: only return the field of 'name', and the condition is searching the users with age range from 18 to 30")
    data = db_api.search_data(table_name=table_name, fields="name", condition="age BETWEEN 18 AND 30", show=True)
    if data is None:
        raise RuntimeError("MySQL test failed.")
    logger.info("Case 2: return the fields of 'name' and 'age', and the condition is searching the users whose age is less than or equal to 18.")
    data = db_api.search_data(table_name=table_name, fields=["name", "age"], condition="age<=18", show=True)
    if data is None:
        raise RuntimeError("MySQL test failed.")
    logger.info("Case 3: return the fields of 'name', 'age' and 'add_date', and return all data")
    data = db_api.search_data(table_name=table_name, fields=["name", "age", "add_date"], list_all=True, show=True)
    if data is None:
        raise RuntimeError("MySQL test failed.")
    logger.info("Case 4: return all fields and all data")
    data = db_api.search_data(table_name=table_name, list_all=True, show=True)
    if data is None:
        raise RuntimeError("MySQL test failed.")
    
    # update data
    if not db_api.update_data(table_name=table_name, data=dict(age=18), condition="BINARY name='Weiming Chen'"):
        raise RuntimeError("MySQL test failed.")
    
    # delete data
    if not db_api.delete_data(table_name=table_name, condition="age>30"):
        raise RuntimeError("MySQL test failed.")
    
    # delete table
    if not db_api.delete_table(table_name=table_name):
        raise RuntimeError("MySQL test failed.")

    db_api.close()
    logger.success("MySQL test passed.")

    ## test SQLite
    logger.info("Testing SQLite...")
    db_api = SQLiteAPI(in_memory=True, logger=logger)

    # create table
    status = db_api.create_table(
        table_name=table_name,
        table_config=[dict(name="id", dtype="integer", not_null=True, primary_key=True, auto_increment=True),
                      dict(name="name", dtype="text", not_null=True),
                      dict(name="age", dtype="integer", not_null=True),
                      dict(name="gender", dtype="text", default="Unknown", not_null=True),
                      dict(name="add_date", dtype="date")]
    )
    if not status:
        raise RuntimeError("SQLite test failed.")
    
    # get tables
    if db_api.get_tables(show=True) is None:
        raise RuntimeError("SQLite test failed.")
    
    # get fields
    if db_api.get_fields(table_name=table_name, show=True) is None:
        raise RuntimeError("SQLite test failed.")
    
    # insert data
    user_data = [dict(name="Weiming Chen", age=27, gender="male", add_date=datetime.now().strftime("%Y-%m-%d")),
                 dict(name="John", age=16, add_date=datetime.now().strftime("%Y-%m-%d")),
                 dict(name="David", age=45, add_date=datetime.now().strftime("%Y-%m-%d")),
                 dict(name="Peter", age=35)]
    for data in user_data:
        if not db_api.insert_data(table_name=table_name, data=data):
            raise RuntimeError("SQLite test failed.")
        
    # search data
    logger.info("Case 1: only return the field of 'name', and the condition is searching the users with age range from 18 to 30")
    data = db_api.search_data(table_name=table_name, fields="name", condition="age BETWEEN 18 AND 30", show=True)
    if data is None:
        raise RuntimeError("SQLite test failed.")
    logger.info("Case 2: return the fields of 'name' and 'age', and the condition is searching the users whose age is less than or equal to 18.")
    data = db_api.search_data(table_name=table_name, fields=["name", "age"], condition="age<=18", show=True)
    if data is None:
        raise RuntimeError("SQLite test failed.")
    logger.info("Case 3: return the fields of 'name', 'age' and 'add_date', and return all data")
    data = db_api.search_data(table_name=table_name, fields=["name", "age", "add_date"], list_all=True, show=True)
    if data is None:
        raise RuntimeError("SQLite test failed.")
    logger.info("Case 4: return all fields and all data")
    data = db_api.search_data(table_name=table_name, list_all=True, show=True)
    if data is None:
        raise RuntimeError("SQLite test failed.")
    
    # update data
    if not db_api.update_data(table_name=table_name, data=dict(age=18), condition="name='Weiming Chen'"):
        raise RuntimeError("SQLite test failed.")
    
    # delete data
    if not db_api.delete_data(table_name=table_name, condition="age>30"):
        raise RuntimeError("SQLite test failed.")
    
    # delete table
    if not db_api.delete_table(table_name=table_name):
        raise RuntimeError("SQLite test failed.")

    db_api.close()
    logger.success("SQLite test passed.")


if __name__ == "__main__":
    run()
