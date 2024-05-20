# Copyright 2024 MuLingCloud
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
MuLingCloud base module: database api

Supported backend: 
- MySQL
- SQLite

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Optional, Union, List

import pymysql
from prettytable import PrettyTable

from .logger import Logger
from .conifg import ConfigDict
from .register import DATABASE
from .misc import is_int, is_float, is_str, is_list

PathLikeType = Union[str, Path]


@DATABASE.register_module()
class MySQLAPI:
    def __init__(self, 
                 host: str, 
                 port: int,
                 user: str,
                 database: str,
                 password: str,
                 charset: str = 'utf8',
                 work_dir: Optional[PathLikeType] = None, 
                 logger: Optional[Logger] = None,
                 quiet: bool = False):
        """An api for MySQL database

        Args:
            host (str)
            port (int)
            user (str)
            database (str)
            password (str)
            charset (str, optional): Defaults to 'utf8'.
            work_dir (Optional[PathLikeType], optional): will save the log file to "work_dir/log/" if 
                                                         work_dir is specified. Defaults to None.
            logger (Optional[Logger], optional): Defaults to None.
            quiet (bool, optional): whether the logger to run in quiet mode. Defaults to False.
        """
        self.work_dir = Path(work_dir) if work_dir is not None else None
        self.logger = self._set_logger(logger, quiet)

        self.__connect(host, port, user, database, password, charset)

    def __connect(self, host, port, user, database, password, charset):
        self.logger.info('connecting to database...')
        try:
            self.conn = pymysql.connect(host=host, 
                                        port=int(port), 
                                        user=user, 
                                        password=password, 
                                        database=database, 
                                        charset=charset)
            self.cursor = self.conn.cursor()
            self.logger.success('database connected')
            self.__host = host
            self.__port = int(port)
            self.__user = user
            self.__database = database
            self.__password = password
            self.__charset = charset
            self.is_connect = True
        except ConnectionError as e:
            self.logger.error(f'database connect error: {str(e)}')
            self.is_connect = False
        
    def ping(self):
        try:
            self.conn.ping()
        except:
            self.logger.info('reconnecting to database...')
            del self.conn
            del self.cursor
            self.__connect(self.__host, self.__port, self.__user, self.__database, self.__password, self.__charset)

    def create_table(self, 
                     table_name: Optional[str] = None, 
                     table_config: Optional[List[dict]] = None, 
                     sql_command: Optional[str] = None, 
                     exist_ok: bool = True,
                     use_ping: bool = True):
        """create data table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            table_config (Optional[List[dict]], optional): Defaults to None.
            sql_command (Optional[str], optional): Defaults to None.
            exist_ok (bool, optional): Defaults to True.
            use_ping (bool, optional): Defaults to True.

        e.g.:
        If you want to create a table named "user" as follows, and set "id" as the primary key.
        | id | name | age | add_date |
        | .. | .... | ... | ........ |
        | .. | .... | ... | ........ |
        | .. | .... | ... | ........ |

        Creating with table_name and table_config:
        >>> create_table(
        >>>     table_name="user",
        >>>     table_config=[dict(name="id", dtype="int", not_null=True, primary_key=True, auto_increment=True),
        >>>                   dict(name="name", dtype="varchar(255)", not_null=True),
        >>>                   dict(name="age", dtype="int", not_null=True),
        >>>                   dict(name="add_date", dtype="date", not_null=True)]
        >>> )
        Besides, you can create it with sql_command directly:
        >>> create_table(sql_command="CREATE TABLE IF NOT EXISTS user("
        >>>                          "id INT NOT NULL AUTO_INCREMENT,"
        >>>                          "name VARCHAR(255) NOT NULL,"
        >>>                          "age INT NOT NULL,"
        >>>                          "add_date DATE NOT NULL,PRIMARY KEY (id))"
        >>>                          "ENGINE=InnoDB DEFAULT CHARSET=utf8")

        Raise:
            SyntaxError: raise when specified more than one primary key

        Returns:
            bool: return True if success, otherwise return False
        """
        self.ping() if use_ping else None
        self.logger.info('creating table...')

        if sql_command is None:
            assert table_name is not None and table_config is not None, \
                'when sql_command is None, both table_name and table_config must be provided'
            assert is_list(table_config), "table_config must be a list"

            tables = self.get_tables(use_ping=False)
            exist_table = tuple(filter(lambda x: x[0] == table_name, tables))
            if len(exist_table) > 0:
                if exist_ok:
                    self.logger.info(f"table '{table_name}' already exists, skipping...")
                    return True
                else:
                    self.logger.warning(f"table '{table_name}' already exists, please try to set exist_ok=True.")
                    return False
            
            sql = f"CREATE TABLE {table_name}("
            primary_key = []
            for field in table_config:
                field = ConfigDict(field)
                command = [field.name]
                command.append(field.dtype.upper())

                if field.get("primary_key", False):
                    primary_key.append(field.name)

                if field.get("auto_increment", False):
                    command.append("AUTO_INCREMENT")

                if field.get("not_null", False):
                    command.append("NOT NULL")

                if field.default is not None:
                    if is_str(field.default):
                        command.append(f"DEFAULT '{field.default}'")
                    else:
                        command.append(f"DEFAULT {field.default}")
                
                sql += " ".join(command) + ","
            if len(primary_key) > 0:
                sql += f"PRIMARY KEY ({','.join(primary_key)}))"
            else:
                sql = sql.strip(",") + ")"
            sql += f"ENGINE=InnoDB DEFAULT CHARSET={self.__charset}"
        else:
            sql = sql_command

        try:
            self.cursor.execute(sql)
            self.conn.commit()
            self.logger.success(f'table created')
            return True
        except Exception as error:
            self.logger.error(f'create table error: {str(error)}')
            return False

    def delete_table(self,
                     table_name: Optional[str] = None,
                     sql_command: Optional[str] = None,
                     not_exist_ok: bool = True,
                     use_ping: bool = True):
        """delete the entire data table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            sql_command (Optional[str], optional): Defaults to None.
            not_exist_ok (bool, optional): Defaults to True.
            use_ping (bool, optional): Defaults to True.

        Returns:
            bool: return True if success, otherwise return False
        """
        self.ping() if use_ping else None
        self.logger.info('deleting data table...')

        if sql_command is None:
            assert table_name is not None, 'when sql_command is None, table_name must be provided'

            tables = self.get_tables(use_ping=False)
            exist_table = tuple(filter(lambda x: x[0] == table_name, tables))
            if len(exist_table) == 0:
                if not_exist_ok:
                    self.logger.info(f"table '{table_name}' does not exist, skipping...")
                    return True
                else:
                    self.logger.warning(f"table '{table_name}' does not exist, please try to set not_exist_ok=True.")
                    return False
                
            sql = f"DROP TABLE {table_name}"
        else:
            sql = sql_command

        try:
            self.cursor.execute(sql)
            self.conn.commit()
            self.logger.success(f'table deleted')
            return True
        except Exception as error:
            self.logger.error(f'delete table error: {str(error)}')
            return False
        
    def get_tables(self,
                   sql_command: Optional[str] = None,
                   show: bool = False,
                   use_ping: bool = True):
        """get all tables' name in the database

        Args:
            sql_command (Optional[str], optional): Defaults to None.
            show (bool, optional): Defaults to False.
            use_ping (bool, optional): Defaults to True.

        Returns:
            tuple or None: return table names in tuple if success, otherwise return None
        """
        self.ping() if use_ping else None
        self.logger.info('getting tables from database...')

        if sql_command is None:
            sql = "SHOW TABLES"
        else:
            sql = sql_command

        try:
            self.cursor.execute(sql)
            data = self.cursor.fetchall()
            self.conn.commit()
            if show:
                table = PrettyTable(["Tables"])
                for item in data:
                    table.add_row(item)
                print(table)
            return data
        except Exception as error:
            self.logger.error(f'get tables error: {str(error)}')
            return None
        
    def get_fields(self,
                   table_name: Optional[str] = None,
                   sql_command: Optional[str] = None,
                   show: bool = False,
                   use_ping: bool = True):
        """get all the information of fields in the table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            sql_command (Optional[str], optional): Defaults to None.
            show (bool, optional): Defaults to False.
            use_ping (bool, optional): Defaults to True.

        Returns:
            tuple or None: return the information of fields in tuple if success, otherwise return None
        """
        self.ping() if use_ping else None
        self.logger.info('getting fields from data table...')
        
        if sql_command is None:
            assert table_name is not None, 'when sql_command is None, table_name must be provided'

            sql = f"SHOW COLUMNS FROM {table_name}"
        else:
            sql = sql_command

        try:
            self.cursor.execute(sql)
            data = self.cursor.fetchall()
            self.conn.commit()
            if show:
                table = PrettyTable(["Field", "Type", "Null", "Key", "Default", "Extra"])
                for item in data:
                    table.add_row(item)
                print(table)
            return data
        except Exception as error:
            self.logger.error(f'get fields error: {str(error)}')
            return None
        
    def insert_data(self,
                    table_name: Optional[str] = None,
                    data: Optional[dict] = None,
                    sql_command: Optional[str] = None, 
                    use_ping: bool = True):
        """insert data into table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            data (Optional[dict], optional): Defaults to None.
            sql_command (Optional[str], optional): Defaults to None.
            use_ping (bool, optional): Defaults to True.

        e.g.:
        If you want to insert data into table "user" as follows.
        | id | name | age | add_date |
        | .. | .... | ... | ........ |
        | .. | .... | ... | ........ |
        | .. | .... | ... | ........ |

        Inserting with table_name and data:
        >>> insert_data(
        >>>     table_name="user",
        >>>     # id will be auto-incremented, do not need to specify
        >>>     data=dict(name="Weiming Chen", age=27, add_date="2024-04-12")
        >>> )
        Besides, you can insert it with sql_command directly:
        >>> insert_data(sql_command="INSERT INTO user (name,age,add_date) "
        >>>                         "VALUES ('Weiming Chen',27,'2024-04-12')")

        Returns:
            bool: return True if success, otherwise return False
        """
        self.ping() if use_ping else None
        self.logger.info('inserting data...')
        
        if sql_command is None:
            assert table_name is not None and data is not None, \
                'when sql_command is None, both table_name and data must be provided'
            
            sql_keys = ""
            sql_values = ""
            for k, v in data.items():
                sql_keys += f"{k},"
                if is_str(v):
                    sql_values += f"'{v}',"
                if is_int(v) or is_float(v):
                    sql_values += f"{v},"
                if v is None:
                    sql_values += f"NULL,"
            sql_keys = sql_keys.strip(",")
            sql_values = sql_values.strip(",")
            sql = f"INSERT INTO {table_name} ({sql_keys}) VALUES ({sql_values})"
        else:
            sql = sql_command

        try:
            self.cursor.execute(sql)
            self.conn.commit()
            self.logger.success(f'data inserted')
            return True
        except Exception as error:
            self.logger.error(f'insert data error: {str(error)}')
            return False
        
    def search_data(self,
                    table_name: Optional[str] = None,
                    fields: Optional[Union[List[str], str]] = None,
                    condition: Optional[str] = None,
                    list_all: bool = False,
                    sql_command: Optional[str] = None,
                    show: bool = False,
                    use_ping: bool = True):
        """search data from table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            fields (Optional[Union[List[str], str]], optional): Defaults to None.
            condition (Optional[str], optional): Defaults to None.
            list_all (bool, optional): Defaults to False.
            sql_command (Optional[str], optional): Defaults to None.
            show (bool, optional): Defaults to False.
            use_ping (bool, optional): Defaults to True.

        e.g.:
        If you want to search data from table "user" as follows.
        | id | name | age | add_date |
        | .. | .... | ... | ........ |
        | .. | .... | ... | ........ |
        | .. | .... | ... | ........ |

        Case 1: search users with age range from 18 to 30, and return their names and adding dates.
        Searching with table_name, fields and condition:
        >>> search_data(
        >>>     table_name="user", 
        >>>     fields=["name", "add_date"],
        >>>     condition="age BETWEEN 18 AND 30"
        >>> )
        Besides, you can search it with sql_command directly:
        >>> search_data(sql_command="SELECT name,add_date FROM user WHERE age BETWEEN 18 AND 30")

        Case 2: list all users' name in table.
        Searching with table_name, fields and list_all:
        >>> search_data(table_name="user", fields="name", list_all=True)
        Besides, you can search it with sql_command directly:
        >>> search_data(sql_command="SELECT name FROM user")

        Case 3: list all data in table.
        Searching with table_name and list_all:
        >>> search_data(table_name="user", list_all=True)
        Besides, you can search it with sql_command directly:
        >>> search_data(sql_command="SELECT * FROM user")

        Notice: 
        If your condition parameter is str, we highly recommended you to use "BINARY" in your condition.
        Because the SQL syntax is not sensitive with the case of letters, the following condition without
        the keyword of "BINARY" will cause ambiguity.
        >>> 😰 condition="name='Weiming Chen'"
        For example, if you want to search data with name "Weiming Chen", the following condition will not
        cause ambiguity.
        >>> 😄 condition="BINARY name='Weiming Chen'"
        
        Returns:
            tuple or None: return data in tuple if success, otherwise return None.
        """
        self.ping() if use_ping else None
        self.logger.info('searching data...')

        if sql_command is None:
            assert table_name is not None, 'when sql_command is None, table_name must be provided'
            if fields is not None:
                assert is_list(fields) or is_str(fields), 'when fields is not None, it must be a list or str'
                if is_str(fields):
                    fields = [fields]
            else:
                fields = []
                fields_info = self.get_fields(table_name=table_name, use_ping=False)
                for item in fields_info:
                    fields.append(item[0])
            fields = ",".join(fields)
            
            if not list_all:
                assert condition is not None, 'when sql_command is None and list_all=False, condition must be provided'

                sql = f"SELECT {fields} FROM {table_name} WHERE {condition}"
            else:
                sql = f"SELECT {fields} FROM {table_name}"
        else:
            sql = sql_command

        try:
            self.cursor.execute(sql)
            data = self.cursor.fetchall()
            self.conn.commit()
            if show and sql_command is None:
                fields = fields.split(",")
                table = PrettyTable(fields)
                for item in data:
                    table.add_row(item)
                print(table)
            return data
        except Exception as error:
            self.logger.error(f'search data error: {str(error)}')
            return None
        
    def update_data(self,
                    table_name: Optional[str] = None,
                    data: Optional[Union[dict]] = None,
                    condition: Optional[str] = None,
                    sql_command: Optional[str] = None,
                    use_ping: bool = True):
        """update data in table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            data (Optional[Union[dict]], optional): Defaults to None.
            condition (Optional[str], optional): Defaults to None.
            sql_command (Optional[str], optional): Defaults to None.
            use_ping (bool, optional): Defaults to True.

        e.g.:
        If you want to update data in table "user" as follows. 
        Specifically, change my age to 18.
        | id | name | age | add_date |
        | .. | .... | ... | ........ |
        | .. | .... | ... | ........ |
        | .. | .... | ... | ........ |

        Updating with table_name and data:
        >>> update_data(
        >>>     table_name="user",
        >>>     data=dict(age=18),
        >>>     condition="BINARY name='Weiming Chen'"
        >>> )
        Besides, you can update it with sql_command directly:
        >>> update_data(sql_command="UPDATE user SET age=18 WHERE BINARY name='Weiming Chen'")

        Returns:
            bool: return True if success, otherwise return False
        """
        self.ping() if use_ping else None
        self.logger.info('updating data...')

        if sql_command is None:
            assert table_name is not None and data is not None and condition is not None, \
                'when sql_command is None, both table_name, data and condition must be provided'
            
            sql_values = ""
            for k, v in data.items():
                if is_str(v):
                    sql_values += f"{k}='{v}',"
                if is_int(v) or is_float(v):
                    sql_values += f"{k}={v},"
                if v is None:
                    sql_values += f"{k}=NULL,"
            sql_values = sql_values.strip(",")
            sql = f"UPDATE {table_name} SET {sql_values} WHERE {condition}"
        else:
            sql = sql_command
        
        try:
            self.cursor.execute(sql)
            self.conn.commit()
            self.logger.success(f'data updated')
            return True
        except Exception as error:
            self.logger.error(f'update data error: {str(error)}')
            return False
        
    def delete_data(self, 
                    table_name: Optional[str] = None, 
                    condition: Optional[str] = None, 
                    sql_command: Optional[str] = None,
                    use_ping: bool = True):
        """delete data from table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            condition (Optional[str], optional): Defaults to None.
            sql_command (Optional[str], optional): Defaults to None.
            use_ping (bool, optional): Defaults to True.

        e.g.:
        If you want to delete data from table "user" as follows. 
        Specifically, delete users younger than 18.
        | id | name | age | add_date |
        | .. | .... | ... | ........ |
        | .. | .... | ... | ........ |
        | .. | .... | ... | ........ |

        Deleting with table_name and condition:
        >>> delete_data(table_name="user", condition="age<18")
        Besides, you can delete it with sql_command directly:
        >>> delete_data(sql_command="DELETE FROM user WHERE age<18")

        Returns:
            bool: return True if success, otherwise return False
        """
        self.ping() if use_ping else None
        self.logger.info('deleting data...')

        if sql_command is None:
            assert table_name is not None and condition is not None, \
                'when sql_command is None, both table_name and condition must be provided'

            sql = f"DELETE FROM {table_name} WHERE {condition}"
        else:
            sql = sql_command
        
        try:
            self.cursor.execute(sql)
            self.conn.commit()
            self.logger.success(f'data deleted')
            return True
        except Exception as error:
            self.logger.error(f'delete data error: {str(error)}')
            return False
        
    def close(self):
        try:
            self.cursor.close()
            self.conn.close()
            self.logger.info('database connection closed')
        except Exception as error:
            del self.cursor
            del self.conn
            self.logger.error(str(error))

    def _set_logger(self, logger: Optional[Logger], quiet: bool):
        if logger is None:
            now_time = datetime.now().strftime('%Y%m%d-%H%M%S')
            logger = Logger()
            if self.work_dir is not None:
                logger.init_logger(save_path=self.work_dir/'log'/f'{now_time}.log')
            else:
                logger.init_logger()
        if quiet:
            logger.set_quiet()
        else:
            logger.set_activate()
        return logger


@DATABASE.register_module()
class SQLiteAPI:
    def __init__(self,
                 db_path: Optional[str] = None,
                 in_memory: bool = False,
                 work_dir: Optional[PathLikeType] = None, 
                 logger: Optional[Logger] = None,
                 quiet: bool = False):
        self.work_dir = Path(work_dir) if work_dir is not None else None
        self.logger = self._set_logger(logger, quiet)
        
        if db_path is None and not in_memory:
            self.logger.error('db_path or in_memory must be provided')
            raise ValueError('db_path or in_memory must be provided')

        if db_path is not None:
            if not Path(db_path).exists():
                self.logger.error(f'No such file: {db_path}')
                raise FileNotFoundError(f'No such file: {db_path}')
            if Path(db_path).suffix not in [".db", ".db3", ".sqlite", ".sqlite3"]:
                self.logger.error(f'Unsupported suffix: {Path(db_path).suffix}')
                raise ValueError(f'Unsupported suffix: {Path(db_path).suffix}')
        
        self.db_path = db_path
        self.in_memory = in_memory

        self.__connect()

    def __connect(self):
        self.logger.info('connecting to database...')
        try:
            if self.in_memory:
                path = ":memory:"
            else:
                path = self.db_path
            self.conn = sqlite3.connect(path)
            self.cursor = self.conn.cursor()
            self.logger.success('database connected')
            self.is_connect = True
        except ConnectionError as e:
            self.logger.error(f'database connect error: {str(e)}')
            self.is_connect = False
        
    def create_table(self,
                     table_name: Optional[str] = None, 
                     table_config: Optional[List[dict]] = None, 
                     sql_command: Optional[str] = None,
                     exist_ok: bool = True):
        """create data table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            table_config (Optional[List[dict]], optional): Defaults to None.
            sql_command (Optional[str], optional): Defaults to None.
            exist_ok (bool, optional): Defaults to True.

        Raises:
            SyntaxError: when specifying AUTOINCREMENT on a non-INTEGER or not PRIMARY KEY field
                         or when creating table with multiple primary keys and auto increment at the same time
            
        Returns:
            bool: return True if success, otherwise return False
        """
        self.logger.info('creating table...')

        if sql_command is None:
            assert table_name is not None and table_config is not None, \
                'when sql_command is None, both table_name and table_config must be provided'
            assert is_list(table_config), "table_config must be a list"

            tables = self.get_tables()
            exist_table = tuple(filter(lambda x: x[0] == table_name, tables))
            if len(exist_table) > 0:
                if exist_ok:
                    self.logger.info(f"table '{table_name}' already exists, skipping...")
                    return True
                else:
                    self.logger.warning(f"table '{table_name}' already exists, please try to set exist_ok=True.")
                    return False
            
            primary_key_num = 0
            has_auto_increment = False
            for field in table_config:
                field = ConfigDict(field)
                if field.get("primary_key", False):
                    primary_key_num += 1
                if field.get("auto_increment", False):
                    has_auto_increment = True
            if primary_key_num > 1 and has_auto_increment:
                self.logger.warning("SQLite does not support creating a table with multiple primary keys and "
                                    "auto increment field at the same time.")
                raise SyntaxError("SQLite does not support creating a table with multiple primary keys and "
                                  "auto increment field at the same time.")
            
            sql = f"CREATE TABLE {table_name} ("
            primary_key = []
            for field in table_config:
                field = ConfigDict(field)
                command = [field.name]
                command.append(field.dtype.upper())

                if field.get("primary_key", False):
                    primary_key.append(field.name)
                    if primary_key_num == 1:
                        command.append("PRIMARY KEY")
                    
                if field.get("auto_increment", False):
                    if field.dtype.upper() != "INTEGER" or not field.get("primary_key", False):
                        self.logger.error("AUTOINCREMENT is only allowed on an INTEGER PRIMARY KEY")
                        raise SyntaxError("AUTOINCREMENT is only allowed on an INTEGER PRIMARY KEY")
                    command.append("AUTOINCREMENT")

                if field.get("not_null", False):
                    command.append("NOT NULL")

                if field.default is not None:
                    if is_str(field.default):
                        command.append(f"DEFAULT '{field.default}'")
                    else:
                        command.append(f"DEFAULT {field.default}")

                sql += " ".join(command) + ","
            
            if len(primary_key) > 1:
                sql += f"PRIMARY KEY ({','.join(primary_key)}))"
            else:
                sql = sql.strip(",") + ")"
        else:
            sql = sql_command

        try:
            self.cursor.execute(sql)
            self.conn.commit()
            self.logger.success(f'table created')
            return True
        except Exception as error:
            self.logger.error(f'create table error: {str(error)}')
            return False
        
    def delete_table(self,
                     table_name: Optional[str] = None,
                     sql_command: Optional[str] = None,
                     not_exist_ok: bool = True):
        """delete the entire data table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            sql_command (Optional[str], optional): Defaults to None.
            not_exist_ok (bool, optional): Defaults to True.

        Returns:
            bool: return True if success, otherwise return False
        """
        self.logger.info('deleting data table...')

        if sql_command is None:
            assert table_name is not None, 'when sql_command is None, table_name must be provided'

            tables = self.get_tables()
            exist_table = tuple(filter(lambda x: x[0] == table_name, tables))
            if len(exist_table) == 0:
                if not_exist_ok:
                    self.logger.info(f"table '{table_name}' does not exist, skipping...")
                    return True
                else:
                    self.logger.warning(f"table '{table_name}' does not exist, please try to set not_exist_ok=True.")
                    return False
                
            sql = f"DROP TABLE {table_name}"
        else:
            sql = sql_command

        try:
            self.cursor.execute(sql)
            self.conn.commit()
            self.logger.success(f'table deleted')
            return True
        except Exception as error:
            self.logger.error(f'delete table error: {str(error)}')
            return False

    def get_tables(self,
                   sql_command: Optional[str] = None,
                   show: bool = False,
                   return_sqlite_sequence: bool = False):
        """get all tables' name in the database

        Args:
            sql_command (Optional[str], optional): Defaults to None.
            show (bool, optional): Defaults to False.
            return_sqlite_sequence (bool, optional): whether to return the "sqlite_sequence" table. Defaults to False.

        Returns:
            tuple or None: return table names in tuple if success, otherwise return None
        """
        self.logger.info('getting tables from database...')

        if sql_command is None:
            sql = "SELECT name FROM sqlite_master WHERE type='table'"
        else:
            sql = sql_command

        try:
            self.cursor.execute(sql)
            data = self.cursor.fetchall()
            self.conn.commit()
            if not return_sqlite_sequence:
                data = tuple(filter(lambda x: x[0] != "sqlite_sequence", data))
            if show:
                table = PrettyTable(["Tables"])
                for item in data:
                    table.add_row(item)
                print(table)
            return tuple(data)
        except Exception as error:
            self.logger.error(f'get tables error: {str(error)}')
            return None
        
    def get_fields(self,
                   table_name: Optional[str] = None,
                   sql_command: Optional[str] = None,
                   show: bool = False):
        """get all the information of fields in the table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            sql_command (Optional[str], optional): Defaults to None.
            show (bool, optional): Defaults to False.

        Returns:
            tuple or None: return the information of fields in tuple if success, otherwise return None
        """
        self.logger.info('getting fields from data table...')
        
        if sql_command is None:
            assert table_name is not None, 'when sql_command is None, table_name must be provided'

            sql = f"PRAGMA table_info({table_name})"
        else:
            sql = sql_command

        try:
            self.cursor.execute(sql)
            data = self.cursor.fetchall()
            self.conn.commit()
            if show:
                table = PrettyTable(["Column", "Field", "Type", "Not Null", "Default", "Primary Key"])
                for item in data:
                    table.add_row(item)
                print(table)
            return tuple(data)
        except Exception as error:
            self.logger.error(f'get fields error: {str(error)}')
            return None
        
    def insert_data(self,
                    table_name: Optional[str] = None,
                    data: Optional[dict] = None,
                    sql_command: Optional[str] = None):
        """insert data into table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            data (Optional[dict], optional): Defaults to None.
            sql_command (Optional[str], optional): Defaults to None.

        Returns:
            bool: return True if success, otherwise return False
        """
        self.logger.info('inserting data...')
        
        if sql_command is None:
            assert table_name is not None and data is not None, \
                'when sql_command is None, both table_name and data must be provided'
            
            sql_keys = ""
            sql_values = ""
            for k, v in data.items():
                sql_keys += f"{k},"
                if is_str(v):
                    sql_values += f"'{v}',"
                if is_int(v) or is_float(v):
                    sql_values += f"{v},"
                if v is None:
                    sql_values += f"NULL,"
            sql_keys = sql_keys.strip(",")
            sql_values = sql_values.strip(",")
            sql = f"INSERT INTO {table_name} ({sql_keys}) VALUES ({sql_values})"
        else:
            sql = sql_command

        try:
            self.cursor.execute(sql)
            self.conn.commit()
            self.logger.success(f'data inserted')
            return True
        except Exception as error:
            self.logger.error(f'insert data error: {str(error)}')
            return False
        
    def search_data(self,
                    table_name: Optional[str] = None,
                    fields: Optional[Union[List[str], str]] = None,
                    condition: Optional[str] = None,
                    list_all: bool = False,
                    sql_command: Optional[str] = None,
                    show: bool = False):
        """search data from table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            fields (Optional[Union[List[str], str]], optional): Defaults to None.
            condition (Optional[str], optional): Defaults to None.
            list_all (bool, optional): Defaults to False.
            sql_command (Optional[str], optional): Defaults to None.
            show (bool, optional): Defaults to False.
        
        Returns:
            tuple or None: return data in tuple if success, otherwise return None.
        """
        self.logger.info('searching data...')

        if sql_command is None:
            assert table_name is not None, 'when sql_command is None, table_name must be provided'
            if fields is not None:
                assert is_list(fields) or is_str(fields), 'when fields is not None, it must be a list or str'
                if is_str(fields):
                    fields = [fields]
            else:
                fields = []
                fields_info = self.get_fields(table_name=table_name)
                for item in fields_info:
                    fields.append(item[1])
            fields = ",".join(fields)
            
            if not list_all:
                assert condition is not None, 'when sql_command is None and list_all=False, condition must be provided'

                sql = f"SELECT {fields} FROM {table_name} WHERE {condition}"
            else:
                sql = f"SELECT {fields} FROM {table_name}"
        else:
            sql = sql_command

        try:
            self.cursor.execute(sql)
            data = self.cursor.fetchall()
            self.conn.commit()
            if show and sql_command is None:
                fields = fields.split(",")
                table = PrettyTable(fields)
                for item in data:
                    table.add_row(item)
                print(table)
            return tuple(data)
        except Exception as error:
            self.logger.error(f'search data error: {str(error)}')
            return None
        
    def update_data(self,
                    table_name: Optional[str] = None,
                    data: Optional[Union[dict]] = None,
                    condition: Optional[str] = None,
                    sql_command: Optional[str] = None):
        """update data in table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            data (Optional[Union[dict]], optional): Defaults to None.
            condition (Optional[str], optional): Defaults to None.
            sql_command (Optional[str], optional): Defaults to None.

        Returns:
            bool: return True if success, otherwise return False
        """
        self.logger.info('updating data...')

        if sql_command is None:
            assert table_name is not None and data is not None and condition is not None, \
                'when sql_command is None, both table_name, data and condition must be provided'
            
            sql_values = ""
            for k, v in data.items():
                if is_str(v):
                    sql_values += f"{k}='{v}',"
                if is_int(v) or is_float(v):
                    sql_values += f"{k}={v},"
                if v is None:
                    sql_values += f"{k}=NULL,"
            sql_values = sql_values.strip(",")
            sql = f"UPDATE {table_name} SET {sql_values} WHERE {condition}"
        else:
            sql = sql_command
        
        try:
            self.cursor.execute(sql)
            self.conn.commit()
            self.logger.success(f'data updated')
            return True
        except Exception as error:
            self.logger.error(f'update data error: {str(error)}')
            return False
        
    def delete_data(self, 
                    table_name: Optional[str] = None, 
                    condition: Optional[str] = None, 
                    sql_command: Optional[str] = None):
        """delete data from table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            condition (Optional[str], optional): Defaults to None.
            sql_command (Optional[str], optional): Defaults to None.
            use_ping (bool, optional): Defaults to True.

        Returns:
            bool: return True if success, otherwise return False
        """
        self.logger.info('deleting data...')

        if sql_command is None:
            assert table_name is not None and condition is not None, \
                'when sql_command is None, both table_name and condition must be provided'

            sql = f"DELETE FROM {table_name} WHERE {condition}"
        else:
            sql = sql_command
        
        try:
            self.cursor.execute(sql)
            self.conn.commit()
            self.logger.success(f'data deleted')
            return True
        except Exception as error:
            self.logger.error(f'delete data error: {str(error)}')
            return False
        
    def close(self):
        try:
            self.cursor.close()
            self.conn.close()
            self.logger.info('database connection closed')
        except Exception as error:
            del self.cursor
            del self.conn
            self.logger.error(str(error))

    def _set_logger(self, logger: Optional[Logger], quiet: bool):
        if logger is None:
            now_time = datetime.now().strftime('%Y%m%d-%H%M%S')
            logger = Logger()
            if self.work_dir is not None:
                logger.init_logger(save_path=self.work_dir/'log'/f'{now_time}.log')
            else:
                logger.init_logger()
        if quiet:
            logger.set_quiet()
        else:
            logger.set_activate()
        return logger
