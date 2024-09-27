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
from typing import Optional, Any, Union
from dataclasses import dataclass
from rich.console import Console
from rich.style import Style
from rich.color import Color
from rich.progress import (Progress, ProgressSample, SpinnerColumn, TextColumn, BarColumn, 
                           TaskProgressColumn, TimeElapsedColumn, TimeRemainingColumn, Task, TaskID)


@dataclass
class TaskWithEmojiStatus(Task):

    @property
    def emoji_status(self) -> Optional[str]:
        if self.total is None:
            return None
        percent = self.completed / self.total
        if 0 <= percent < 0.1:
            return "😴"
        elif 0.1 <= percent < 0.2:
            return "😪"
        elif 0.2 <= percent < 0.3:
            return "😕"
        elif 0.3 <= percent < 0.4:
            return "😐"
        elif 0.4 <= percent < 0.5:
            return "🙂"
        elif 0.5 <= percent < 0.6:
            return "😉"
        elif 0.6 <= percent < 0.7:
            return "😊"
        elif 0.7 <= percent < 0.8:
            return "😄"
        elif 0.8 <= percent < 0.9:
            return "😁"
        elif 0.9 <= percent < 1.0:
            return "🤩"
        else:
            return "🥳"


class EmojiProgressBar(Progress):

    def __init__(self, 
                 total: Union[int, float], 
                 desc: Optional[str] = None, 
                 desc_color: Union[str, tuple] = "red", 
                 color_system: str = "truecolor",
                 **kwargs):
        """emoji progress bar

        Args:
            total (Union[int, float]): total number of the task
            desc (Optional[str], optional): description of the task. Defaults to None.
            desc_color (Union[str, tuple]): color of the description. Support color name or RGB triplet for input. 
                                            Defaults to "red".
            color_system (str): color system in `rich`. Defaults to "truecolor".
        """
        console = kwargs.pop("console", None)
        if desc is not None:
            if isinstance(desc_color, tuple):
                desc_color = Color.from_rgb(*desc_color)
                style = Style(color=desc_color)
                desc_color_name = desc_color.name
            else:
                style = None
                desc_color_name = desc_color
            desc = f"[{desc_color_name}]{desc}"
            console = Console(color_system=color_system, style=style)
        else:
            desc = ""

        columns = (
            SpinnerColumn(),
            TextColumn("{task.description}"),
            BarColumn(),
            TextColumn("{task.emoji_status}"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        )
        super().__init__(*columns, console=console, **kwargs)

        self._cur_task_id = self.add_task(desc, total=total)
    
    def add_task(
        self,
        description: str,
        start: bool = True,
        total: Optional[float] = 100.0,
        completed: int = 0,
        visible: bool = True,
        **fields: Any,
    ) -> TaskID:
        """Add a new 'task' to the Progress display.

        Args:
            description (str): A description of the task.
            start (bool, optional): Start the task immediately (to calculate elapsed time). If set to False,
                you will need to call `start` manually. Defaults to True.
            total (float, optional): Number of total steps in the progress if known.
                Set to None to render a pulsing animation. Defaults to 100.
            completed (int, optional): Number of steps completed so far. Defaults to 0.
            visible (bool, optional): Enable display of the task. Defaults to True.
            **fields (str): Additional data fields required for rendering.

        Returns:
            TaskID: An ID you can use when calling `update`.
        """
        with self._lock:
            task = TaskWithEmojiStatus(
                self._task_index,
                description,
                total,
                completed,
                visible=visible,
                fields=fields,
                _get_time=self.get_time,
                _lock=self._lock,
            )
            self._tasks[self._task_index] = task
            if start:
                self.start_task(self._task_index)
            new_task_index = self._task_index
            self._task_index = TaskID(int(self._task_index) + 1)
        self.refresh()
        return new_task_index
    
    def update(self, advance: Union[int, float], **kwargs: Any):
        """update the progress of the current task.

        Args:
            advance (Union[int, float]): Add a value to task
        """
        kwargs.pop("advance", None)
        self._update(self._cur_task_id, advance=advance, **kwargs)

    def force_finish(self):
        """force to finish the current task
        """
        total = self._tasks[self._cur_task_id].total
        self._update(self._cur_task_id, completed=total)

    def _update(
        self,
        task_id: TaskID,
        *,
        total: Optional[float] = None,
        completed: Optional[float] = None,
        advance: Optional[float] = None,
        description: Optional[str] = None,
        visible: Optional[bool] = None,
        refresh: bool = False,
        **fields: Any,
    ) -> None:
        """Update information associated with a task.

        Args:
            task_id (TaskID): Task id (returned by add_task).
            total (float, optional): Updates task.total if not None.
            completed (float, optional): Updates task.completed if not None.
            advance (float, optional): Add a value to task.completed if not None.
            description (str, optional): Change task description if not None.
            visible (bool, optional): Set visible flag if not None.
            refresh (bool): Force a refresh of progress information. Default is False.
            **fields (Any): Additional data fields required for rendering.
        """
        with self._lock:
            task = self._tasks[task_id]
            completed_start = task.completed

            if total is not None and total != task.total:
                task.total = total
                task._reset()
            if advance is not None:
                task.completed += advance
            if completed is not None:
                task.completed = completed
            if description is not None:
                task.description = description
            if visible is not None:
                task.visible = visible
            task.fields.update(fields)
            update_completed = task.completed - completed_start

            current_time = self.get_time()
            old_sample_time = current_time - self.speed_estimate_period
            _progress = task._progress

            popleft = _progress.popleft
            while _progress and _progress[0].timestamp < old_sample_time:
                popleft()
            if update_completed > 0:
                _progress.append(ProgressSample(current_time, update_completed))
            if (
                task.total is not None
                and task.completed >= task.total
                and task.finished_time is None
            ):
                task.finished_time = task.elapsed

        if refresh:
            self.refresh()
