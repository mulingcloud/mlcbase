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

Support backend: MySQL

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
from pathlib import Path
from datetime import datetime
from typing import Optional, Union, List

import pymysql

from .logger import Logger
from .conifg import ConfigDict
from .misc import is_int, is_float, is_str, is_list

PathLikeType = Union[str, Path]


class MySQLAPI:
    def __init__(self, 
                 host: str, 
                 port: int,
                 user: str,
                 database: str,
                 password: str,
                 charset: str = 'utf-8',
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
            charset (str, optional): Defaults to 'utf-8'.
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
            self.conn = pymysql.connect(host=host, port=port, user=user, password=password, database=database, charset=charset)
            self.cursor = self.conn.cursor()
            self.logger.success('database connected')
            self.__host = host
            self.__port = port
            self.__user = user
            self.__database = database
            self.__password = password
            self.__charset = charset
        except ConnectionError as e:
            self.logger.error(f'database connect error: {str(e)}')
            raise ConnectionError(f'database connect error: {str(e)}')
        
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
                     table_config: Optional[Union[ConfigDict, dict]] = None, 
                     sql_command: Optional[str] = None, 
                     use_ping: bool = True):
        """create data table

        Args:
            table_name (Optional[ConfigDict], optional): Defaults to None.
            table_config (Optional[Union[ConfigDict, dict]], optional): Defaults to None.
            sql_command (Optional[str], optional): Defaults to None.
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
        >>>     table_config=dict(id="INT NOT NULL AUTO_INCREMENT",
        >>>                       name="VARCHAR(255) NOT NULL",
        >>>                       age="INT NOT NULL",
        >>>                       add_date="DATE NOT NULL",
        >>>                       primary_key="id")
        >>> )
        Besides, you can create it with sql_command directly:
        >>> create_table(sql_command="CREATE TABLE user(id INT NOT NULL AUTO_INCREMENT,"
        >>>                          "name VARCHAR(255) NOT NULL,age INT NOT NULL,"
        >>>                          "add_date DATE NOT NULL,PRIMARY KEY (id))"
        >>>                          "ENGINE=InnoDB DEFAULT CHARSET=utf8")

        Returns:
            bool: return True if success, otherwise return False
        """
        self.ping() if use_ping else None
        self.logger.info('creating table...')

        if sql_command is None:
            assert table_name is not None and table_config is not None, \
                'when sql_command is None, both table_name and table_config must be provided'
            
            primary_key_attribute = table_config.pop('primary_key', None)
            sql = f"CREATE TABLE {table_name}("
            for k, v in table_config.items():
                sql += f"{k} {v},"
            if primary_key_attribute is not None:
                sql += f"PRIMARY KEY ({primary_key_attribute})"
            sql = sql.strip(",")
            sql += f")ENGINE=InnoDB DEFAULT CHARSET={self.__charset}"
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
        
    def insert_data(self,
                    table_name: Optional[str] = None,
                    data: Optional[Union[ConfigDict, dict]] = None,
                    sql_command: Optional[str] = None, 
                    use_ping: bool = True):
        """insert data into table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            data (Optional[Union[ConfigDict, dict]], optional): Defaults to None.
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
            bool: status
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
            bool: status
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

    def search_data(self,
                    table_name: Optional[str] = None,
                    attributes: Optional[Union[List[str], str]] = None,
                    condition: Optional[str] = None,
                    list_all: bool = False,
                    sql_command: Optional[str] = None,
                    use_ping: bool = True):
        """search data from table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            attributes (Optional[Union[List[str], str]], optional): Defaults to None.
            condition (Optional[str], optional): Defaults to None.
            list_all (bool, optional): Defaults to False.
            sql_command (Optional[str], optional): Defaults to None.
            use_ping (bool, optional): Defaults to True.

        e.g.:
        If you want to search data from table "user" as follows.
        | id | name | age | add_date |
        | .. | .... | ... | ........ |
        | .. | .... | ... | ........ |
        | .. | .... | ... | ........ |

        Case 1: search users with age range from 18 to 30, and return their names and adding dates.
        Searching with table_name, attributes and condition:
        >>> search_data(
        >>>     table_name="user", 
        >>>     attributes=["name", "add_date"],
        >>>     condition="age BETWEEN 18 AND 30"
        >>> )
        Besides, you can search it with sql_command directly:
        >>> search_data(sql_command="SELECT name,add_date FROM user WHERE age BETWEEN 18 AND 30")

        Case 2: list all users' name in table.
        Searching with table_name, attributes and list_all:
        >>> search_data(table_name="user", attributes="name", list_all=True)
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
            tuple: data
            None: error
        """
        self.ping() if use_ping else None
        self.logger.info('searching data...')

        if sql_command is None:
            assert table_name is not None, \
                'when sql_command is None, table_name must be provided'
            if attributes is not None:
                assert is_list(attributes) or is_str(attributes), \
                    'when attributes is not None, it must be a list or str'
                if is_str(attributes):
                    attributes = [attributes]
            else:
                attributes = ['*']
            attributes = ",".join(attributes)
            
            if not list_all:
                assert condition is not None, \
                    'when sql_command is None and list_all=False, condition must be provided'

                sql = f"SELECT {attributes} FROM {table_name} WHERE {condition}"
            else:
                sql = f"SELECT {attributes} FROM {table_name}"
        else:
            sql = sql_command

        try:
            self.cursor.execute(sql)
            data = self.cursor.fetchall()
            self.conn.commit()
            return data
        except Exception as error:
            self.logger.error(f'search data error: {str(error)}')
            return None
        
    def update_data(self,
                    table_name: Optional[str] = None,
                    data: Optional[Union[ConfigDict, dict]] = None,
                    condition: Optional[str] = None,
                    sql_command: Optional[str] = None,
                    use_ping: bool = True):
        """update data in table

        Args:
            table_name (Optional[str], optional): Defaults to None.
            data (Optional[Union[ConfigDict, dict]], optional): Defaults to None.
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
            bool: status
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
