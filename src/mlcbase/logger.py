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
MuLingCloud base module: logger

Repository: https://github.com/wmchen/pylog or https://gitee.com/wm-chen/pylog

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, TextIO, Optional, Union

import pytz
from loguru._logger import Logger as _Logger
from loguru._logger import Core as _Core


PathLikeType = Union[str, Path]
FormatType = Union[Dict, str]


class Logger:
    _default_format = dict(log_info=[dict(info="{extra[now_time]}", color="green"),
                                     dict(info="{extra[elapsed]}", color="yellow"),
                                     dict(info="{level}", color="level"),
                                     dict(info="{message}", color="level")],
                           separator=dict(symbol=" | ", color="red"))
    
    def __init__(self, 
                 format: Optional[FormatType] = None,
                 quiet: bool = False):
        self._default_format = self.auto_format(format)
        self._quiet = quiet
        self.logger = _Logger(core=_Core(),
                              exception=None,
                              depth=0,
                              record=False,
                              lazy=False,
                              colors=False,
                              raw=False,
                              capture=True,
                              patchers=[],
                              extra={})
        self.handlers = {}
        self.save_path = None
        self.start_time = None
        self.timezone = None
        self.timeformat = None

    def init_logger(self, 
                    save_path: Optional[PathLikeType] = None,
                    remove_default_handlers: Optional[bool] = True,
                    screen_out: TextIO = sys.stderr, 
                    level: str = "DEBUG",
                    timezone: str = "Asia/Shanghai",
                    timeformat: str = "%Y-%m-%d %H:%M:%S",
                    elapsedformat: str = "%d day(s) %H:%M:%S", 
                    **kwargs):
        """init logger

        Args:
            save_path (Optional[PathLikeType]): the path of log file. Defaults to None.
            remove_default_handlers (Optional[bool]): whether to remove the default handlers. 
                                                      Defaults to True.
            screen_out (optional): the level of terminal output. Defaults to sys.stderr.
            level (str): the level of logger. Defaults to "DEBUG".
            timezone (str): timezone. Defaults to "Asia/Shanghai".
            timeformat (str): datetime format. Defaults to "%Y-%m-%d %H:%M:%S".
            elapsedformat (str): elapsed format. Defaults to "%d day(s) %H:%M:%S".
        """
        assert screen_out in [sys.stderr, sys.stdout]
        assert level in ['TRACE', 'DEBUG', 'INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL']
        if remove_default_handlers:
            self.logger.remove(handler_id=None)
            self.handlers = {}
        
        if self.start_time is None:
            self.start_time = datetime.now()
        if self.timezone != timezone:
            self.timezone = timezone
        if self.timeformat != timeformat:
            self.timeformat = timeformat
        self.logger.configure(extra=dict(now_time=None, elapsed=None),
                              patcher=lambda record: record["extra"].update(now_time=self.get_now_time(self.timezone, self.timeformat),
                                                                            elapsed=self.get_elapsed(elapsedformat)))

        screen_out_handler_id = self.logger.add(screen_out, format=self._default_format, level=level)
        self.handlers['screen_out'] = self.logger._core.handlers[screen_out_handler_id]
        if save_path is not None:
            save_path = Path(save_path)
            assert save_path.suffix == '.log', 'The suffix of log file must be ".log"'
            if not save_path.parent.exists():
                save_path.parent.mkdir(parents=True)
            save_path_handler_id = self.logger.add(save_path, format=self._default_format, level=level, **kwargs)
            self.handlers['save_log'] = self.logger._core.handlers[save_path_handler_id]
            self.save_path = str(save_path.absolute())

    def auto_format(self, format):
        def add(info, color):
            return f"<{color}>{info}</{color}>"
        
        if format is None:
            format = self._default_format.copy()
        
        if isinstance(format, str):
            return format
        elif isinstance(format, dict):
            f = []
            for i in format['log_info']:
                f.append(add(i['info'], i['color']))
            separator = add(format['separator']['symbol'], format['separator']['color'])
            return f"{separator}".join(f)
        else:
            raise TypeError("only support 'str' and 'dict' type of format setting.")
        
    @staticmethod
    def get_now_time(timezone, timeformat):
        return datetime.now(tz=pytz.timezone(timezone)).strftime(timeformat)

    def get_elapsed(self, elapsedformat):
        def format_time(e, format):
            total_seconds = int((e.total_seconds() * 10**6 - e.microseconds) / 10**6)
            smallest_scale = None

            if "%d" in format:
                days = (total_seconds - e.seconds) // 86400
                smallest_scale = "%d"
            else:
                days = 0

            if "%H" in format:
                hours = (total_seconds-(days*86400)) // 3600
                smallest_scale = "%H"
            else:
                hours = 0

            if "%M" in format:
                minutes = (total_seconds-(days*86400)-(hours*3600)) // 60
                smallest_scale = "%M"
            else:
                minutes = 0
                
            if "%S" in format:
                seconds = total_seconds - (days*86400) - (hours*3600) - (minutes*60)
                smallest_scale = "%S"
            else:
                seconds = 0

            if smallest_scale == "%d":
                remain_second = total_seconds - (days*86400)
                if remain_second > 0:
                    days += remain_second / 86400
            
            if smallest_scale == "%H":
                remain_second = total_seconds - (days*86400) - (hours*3600)
                if remain_second > 0:
                    fraction = str(remain_second / 3600)
                    return str(days), f"{hours:02d}.{fraction[2:]}", f"{minutes:02d}", f"{seconds:02d}"
            
            if smallest_scale == "%M":
                remain_second = total_seconds - (days*86400) - (hours*3600) - (minutes*60)
                if remain_second > 0:
                    fraction = str(remain_second / 60)
                    return str(days), f"{hours:02d}", f"{minutes:02d}.{fraction[2:]}", f"{seconds:02d}"
            
            return str(days), f"{hours:02d}", f"{minutes:02d}", f"{seconds:02d}"

        elapsed = datetime.now() - self.start_time
        days, hours, minutes, seconds = format_time(elapsed, elapsedformat)
        
        elapsed_text = ""
        format_flag = False
        format_symbol = ""
        for ch in elapsedformat:
            if ch == "%":
                format_flag = True
                format_symbol += "%"
                continue

            if format_flag:
                format_symbol += ch
                if format_symbol == "%d":
                    elapsed_text += days
                elif format_symbol == "%H":
                    elapsed_text += hours
                elif format_symbol == "%M":
                    elapsed_text += minutes
                elif format_symbol == "%S":
                    elapsed_text += seconds
                else:
                    elapsed_text += format_symbol
                format_symbol = ""
                format_flag = False
            else:
                elapsed_text += ch
                
        return elapsed_text

    def info(self, msg: str):
        if not self._quiet:
            self.logger.info(msg)

    def success(self, msg: str):
        if not self._quiet:
            self.logger.success(msg)

    def warning(self, msg: str):
        if not self._quiet:
            self.logger.warning(msg)

    def error(self, msg: str):
        if not self._quiet:
            self.logger.error(msg)

    def critical(self, msg: str):
        if not self._quiet:
            self.logger.critical(msg)

    def debug(self, msg: str):
        if not self._quiet:
            self.logger.debug(msg)

    def exception(self, msg: str):
        if not self._quiet:
            self.logger.exception(msg)
            
    def trace(self, msg: str):
        if not self._quiet:
            self.logger.trace(msg)

    def set_quiet(self):
        self._quiet = True

    def set_activate(self):
        self._quiet = False
