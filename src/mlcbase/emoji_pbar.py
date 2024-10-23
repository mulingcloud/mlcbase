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
MuLingCloud base module: Emoji progress bar

Author: Weiming Chen
Tester: Weiming Chen
"""
import sys
import os
import re
from typing import Optional
from colorama import Fore
from datetime import datetime, timedelta
from .misc import is_int


class EmojiProgressBar:
    COLOR = dict(black=Fore.BLACK, 
                 red=Fore.RED, 
                 green=Fore.GREEN, 
                 yellow=Fore.YELLOW,
                 blue=Fore.BLUE, 
                 magenta=Fore.MAGENTA, 
                 cyan=Fore.CYAN, 
                 white=Fore.WHITE,
                 lightblack_ex=Fore.LIGHTBLACK_EX, 
                 lightred_ex=Fore.LIGHTRED_EX,
                 lightgreen_ex=Fore.LIGHTGREEN_EX, 
                 lightyellow_ex=Fore.LIGHTYELLOW_EX,
                 lightblue_ex=Fore.LIGHTBLUE_EX, 
                 lightmagenta_ex=Fore.LIGHTMAGENTA_EX,
                 lightcyan_ex=Fore.LIGHTCYAN_EX, 
                 lightwhite_ex=Fore.LIGHTWHITE_EX)
    FORMAT_ITEM = ("desc", "percent", "bar", "postfix", "elapsed", "left_time")

    def __init__(self, 
                 total: int,
                 desc: Optional[str] = None,
                 ascii: str = " ■",
                 bar_width: Optional[int] = None,
                 pbar_format: str = "{desc}{percent}|{bar} {postfix} {elapsed} {left_time}",
                 emoji_progress: list = ["😴", "😪", "😕", "😐", "🙂", "😉", "😊", "😄", "😁", "🤩", "😎"],
                 timeformat: str = "%H:%M:%S",
                 desc_color: str = "red",
                 percent_color: str = "magenta",
                 bar_run_color: str = "blue",
                 bar_finish_color: str = "green",
                 postfix_color: str = "magenta",
                 elapsed_color: str = "yellow",
                 left_time_color: str = "cyan",
                 fit_offset: int = 2):
        """A beautiful progress bar with emoji

        Args:
            total (int): total steps
            desc (Optional[str]): description. Defaults to None.
            ascii (str): display characters, must be 2 characters long. The first character denotes to the 
                         finished status, the second denotes to the waiting status. Defaults to " ■".
            bar_width (Optional[int]): the width of bar. Defaults to None.
            pbar_format (str): the format of the progress bar. desc: Description, percent: percentage completion, 
                               bar: progress bar, postfix: information at postfix, elapsed: elapsed time, left_time: 
                               left time. Defaults to "{desc}{percent}|{bar} {postfix} {elapsed} {left_time}".
            emoji_progress (list): emoji status. Defaults to ("😴", "😪", "😕", "😐", "🙂", "😉", "😊", "😄", 
                                   "😁", "🤩", "😎")
            timeformat (str): datetime format. Defaults to "%H:%M:%S".
            desc_color (str): color of desc. Defaults to "red".
            percent_color (str): color of percent. Defaults to "magenta".
            bar_run_color (str): the color of progress bar before finish. Defaults to "blue".
            bar_finish_color (str): the color of progress bar when finished. Defaults to "green".
            postfix_color (str): color of postfix. Defaults to "magenta".
            elapsed_color (str): color of elapsed. Defaults to "yellow".
            left_time_color (str): color of left_time. Defaults to "cyan".
            fit_offset (int): offset when fit. Defaults to 2.
        """
        assert is_int(total), "total must be an integer"
        self.total = total
        self.completed = 0
        self._last_completed = 0
        self.desc = self._prepare_description(desc)
        
        assert isinstance(ascii, str), "ascii must be a string if provided"
        assert len(ascii) == 2, "ascii must be 2 characters long"
        self._wait_char = ascii[0]
        self._done_char = ascii[1]

        try:
            self._terminal_width, _ = os.get_terminal_size()
        except:
            self._terminal_width = None
            if bar_width is None:
                bar_width = 40
        self.bar_width = bar_width
        if (self._terminal_width is not None) and (bar_width is None):
            self.fit = True
        else:
            self.fit = False

        self.pbar_format = pbar_format
        self._show_items, self._other_char_num = self._format_progress_bar()
        self.emoji_progress = emoji_progress
        assert len(emoji_progress) >= 2, "should include at least 2 emoji status"
        self.timeformat = timeformat
        self.desc_color = self._get_color(desc_color)
        self.percent_color = self._get_color(percent_color)
        self.bar_run_color = self._get_color(bar_run_color)
        self.bar_finish_color = self._get_color(bar_finish_color)
        self.postfix_color = self._get_color(postfix_color)
        self.elapsed_color = self._get_color(elapsed_color)
        self.left_time_color = self._get_color(left_time_color)
        self.fit_offset = fit_offset

        self._start_time = datetime.now()
        self._last_update_time = self._start_time
        self._postfix = ""

        show_text = self._render_progress_par()
        sys.stdout.write("\r" + show_text)
        sys.stdout.flush()

    def update(self, advance: int):
        assert is_int(advance), "advance must be an integer"
        self.completed += advance
        cur_time = datetime.now()
        show_text = self._render_progress_par(cur_time)
        sys.stdout.write("\r" + show_text)
        sys.stdout.flush()
        self._last_completed = self.completed
        self._last_update_time = cur_time

    def set_postfix(self, ordered_dict: dict = None):
        assert isinstance(ordered_dict, dict), "ordered_dict must be a dict"
        postfix_list = []
        for key, value in ordered_dict.items():
            postfix_list.append(f"{key}={value}")
        self._postfix = ", ".join(postfix_list)

    def close(self):
        sys.stdout.write("\n")
        sys.stdout.flush()
        
    def _render_progress_par(self, cur_time: Optional[datetime] = None):
        show_items = dict()

        # description
        if "desc" in self._show_items:
            desc = self.desc_color + self.desc + Fore.RESET
            desc_width = len(self.desc)
            show_items["desc"] = desc

        # percent
        if "percent" in self._show_items:
            percent = f"{self.completed/self.total*100:.0f}%"
            percent_width = len(percent)
            percent = self.percent_color + percent + Fore.RESET
            show_items["percent"] = percent

        # post fix
        if "postfix" in self._show_items:
            postfix = f"{self.completed}/{self.total}"
            if self._postfix != "":
                postfix += f", {self._postfix}"
            postfix = f"[{postfix}]"
            postfix_width = len(postfix)
            postfix = self.postfix_color + postfix + Fore.RESET
            show_items["postfix"] = postfix

        # time
        if self.completed == 0:
            if "elapsed" in self._show_items:
                elapsed = "00:00:00"
                elapsed_width = len(elapsed)
                elapsed = self.elapsed_color + elapsed + Fore.RESET
                show_items["elapsed"] = elapsed
            
            if "left_time" in self._show_items:
                left_time = "00:00:00"
                left_time_width = len(left_time)
                left_time = self.left_time_color + left_time + Fore.RESET
                show_items["left_time"] = left_time
        else:
            # elapsed time
            if "elapsed" in self._show_items:
                elapsed_time = cur_time - self._start_time
                days, hours, minutes, seconds, microseconds = self._format_time(elapsed_time, self.timeformat)
                elapsed = self._format_show_time(days, hours, minutes, seconds, microseconds, self.timeformat)
                elapsed_width = len(elapsed)
                elapsed = self.elapsed_color + elapsed + Fore.RESET
                show_items["elapsed"] = elapsed

            # left time
            if "left_time" in self._show_items:
                cur_completed = self.completed - self._last_completed
                elapsed_unit_time = cur_time - self._last_update_time
                _, _, _, seconds, microseconds = self._format_time(elapsed_unit_time, "%S%f")
                seconds = int(seconds) + int(microseconds) / 10**6
                if seconds == 0:
                    left_time = "00:00:00"
                else:
                    velocity = cur_completed / seconds
                    left_time = timedelta(seconds=int((self.total - self.completed) / velocity))
                    days, hours, minutes, seconds, microseconds = self._format_time(left_time, self.timeformat)
                    left_time = self._format_show_time(days, hours, minutes, seconds, microseconds, self.timeformat)
                left_time_width = len(left_time)
                left_time = self.left_time_color + left_time + Fore.RESET
                show_items["left_time"] = left_time

        # bar
        emoji = self._get_emoji_status()
        emoji_width = 1
        if self.completed < self.total:
            bar_color = self.bar_run_color
        else:
            bar_color = self.bar_finish_color
        if self.fit:
            minus_width = self.fit_offset
            if "desc" in self._show_items:
                minus_width += desc_width
            if "percent" in self._show_items:
                minus_width += percent_width
            if "postfix" in self._show_items:
                minus_width += postfix_width
            if "elapsed" in self._show_items:
                minus_width += elapsed_width
            if "left_time" in self._show_items:
                minus_width += left_time_width
            minus_width += self._other_char_num
            bar_width = self._terminal_width - minus_width
        else:
            bar_width = self.bar_width
        bar_width = bar_width - emoji_width - 1
        done_width = round(bar_width * self.completed / self.total)
        wait_width = bar_width - done_width
        bar = bar_color + done_width*self._done_char + " " + emoji + wait_width*self._wait_char + Fore.RESET
        show_items["bar"] = bar

        show_text = self.pbar_format.format(**show_items)
        
        return show_text

    def _get_color(self, color_name: str):
        assert color_name.lower() in self.COLOR.keys(), f"Invalid color name: {color_name}"
        return self.COLOR[color_name.lower()]

    @staticmethod
    def _prepare_description(desc: Optional[str]):
        if desc is None:
            return ""
        else:
            assert isinstance(desc, str)
            desc = desc.strip(" ")
            if desc[-1] not in [":", "："]:
                desc += ":"
            desc += " "
            return desc
        
    def _get_emoji_status(self):
        percent = float(self.completed / self.total)
        run_emojis = self.emoji_progress[:-1]
        end_emoji = self.emoji_progress[-1]
        intervals = [i * (1.0/len(run_emojis)) for i in range(len(run_emojis)+1)]

        intervals = [i / (len(self.emoji_progress) - 1) for i in range(len(self.emoji_progress))]
        for i in range(len(run_emojis)):
            start = intervals[i]
            end = intervals[i+1]
            if start <= percent < end:
                return self.emoji_progress[i]
        if percent >= 1.0:
            return end_emoji
        
    def _format_progress_bar(self):
        format_items = re.findall(r'\{([^}]*)\}', self.pbar_format)
        for item in format_items:
            if item not in self.FORMAT_ITEM:
                raise ValueError(f"Invalid format item: {item}")
        assert "bar" in format_items, "'bar' should be included in progress bar format"
        other_char = [char for char in re.split(r'\{.*?\}', self.pbar_format) if char]
        return format_items, len("".join(other_char))
    
    @staticmethod
    def _format_time(time: timedelta, timeformat: str):
        if "%d" in timeformat:
            has_day = True
        else:
            has_day = False

        if "%H" in timeformat:
            has_hour = True
        else:
            has_hour = False

        if "%M" in timeformat:
            has_minute = True
        else:
            has_minute = False
        
        if "%S" in timeformat:
            has_second = True
        else:
            has_second = False

        if "%f" in timeformat:
            has_microsecond = True
        else:
            has_microsecond = False

        delta_days = time.days
        delta_seconds = time.seconds
        microseconds = time.microseconds
        hours = delta_seconds // 3600
        minute = (delta_seconds % 3600) // 60
        seconds = delta_seconds % 60
        show_day = 0
        show_hour = 0
        show_minute = 0
        show_second = 0
        show_microsecond = 0

        # if %d not in timeformat, unsqueeze days to hours
        if has_day:
            show_day = delta_days
        else:
            hours += delta_days * 24

        # if %H not in timeformat, unsqueeze hours to minutes
        if has_hour:
            show_hour = hours
        else:
            minute += hours * 60

        # if %M not in timeformat, unsqueeze minutes to seconds
        if has_minute:
            show_minute = minute
        else:
            seconds += minute * 60

        # if %S not in timeformat, unsqueeze seconds to microseconds
        if has_second:
            show_second = seconds
        else:
            microseconds += seconds * 10**6

        # ignore microsecond when %f not exists in timeformat
        if has_microsecond:
            show_microsecond = microseconds

        show_day = str(show_day)
        show_hour = f"{show_hour:02d}"
        show_minute = f"{show_minute:02d}"
        show_second = f"{show_second:02d}"
        show_microsecond = str(show_microsecond)

        return show_day, show_hour, show_minute, show_second, show_microsecond
    
    @staticmethod
    def _format_show_time(days, hours, minutes, seconds, microseconds, timeformat):
        show_text = ""
        format_flag = False
        format_symbol = ""
        for ch in timeformat:
            if ch == "%":
                format_flag = True
                format_symbol += "%"
                continue

            if format_flag:
                format_symbol += ch
                if format_symbol == "%d":
                    show_text += (days)
                elif format_symbol == "%H":
                    show_text += hours
                elif format_symbol == "%M":
                    show_text += minutes
                elif format_symbol == "%S":
                    show_text += seconds
                elif format_symbol == "%f":
                    show_text += microseconds
                else:
                    show_text += format_symbol
                format_symbol = ""
                format_flag = False
            else:
                show_text += ch
                
        return show_text
    
    def __enter__(self):
        return self

    def __del__(self):
        self.close()

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self.close()
        except AttributeError:
            # maybe eager thread cleanup upon external error
            if (exc_type, exc_value, traceback) == (None, None, None):
                raise
