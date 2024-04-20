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
MuLingCloud base module: runtime analysis

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
from functools import wraps
from datetime import datetime
from typing import Callable

from prettytable import PrettyTable

from .misc import is_str

_register_modules = {}
    

class _ModuleTimer:
    def __init__(self, module: Callable):
        self.module = module
        self.module_name = module.__qualname__
        if self.module_name not in _register_modules.keys():
            _register_modules[self.module_name] = dict(elapsed=0, calls=0)

    def __call__(self, *args, **kwargs):
        start_time = datetime.now()
        result = self.module(*args, **kwargs)
        end_time = datetime.now()

        _register_modules[self.module_name]['elapsed'] += int((end_time - start_time).total_seconds() * 10**6)
        _register_modules[self.module_name]['calls'] += 1

        return result


def wrap_module_timer(module: Callable):
    # use it as a decorator: @wrap_module_timer
    @wraps(module)
    def wrapped_function(*args, **kwargs):
        if hasattr(module, "im_self"):
            return _ModuleTimer(module.__get__(module.__self__))(*args, **kwargs)
        else:
            return _ModuleTimer(module)(*args, **kwargs)
    return wrapped_function


def delete_register_modules(name: str = None):
    global _register_modules

    if name is None:
        _register_modules = {}
    else:
        assert name in _register_modules.keys(), f"module {name} is not registered"
        del _register_modules[name]


def runtime_analysis(start_time: datetime = None, 
                     end_time: datetime = None, 
                     unit: str = "ms"):
    """analysis runtime

    Args:
        start_time (datetime, optional): start time of the total program. Defaults to None.
        end_time (datetime, optional): end time of the total program. Defaults to None.
        unit (str, optional): Defaults to "ms".
    """
    assert start_time is None or isinstance(start_time, datetime), "start_time must be a datetime object"
    assert end_time is None or isinstance(end_time, datetime), "end_time must be a datetime object"
    assert is_str(unit) and unit.lower() in ["h", "min", "s", "ms", "us"], \
        "the unit must be one of ['h', 'min', 's', 'ms', 'us']"

    module_list = list()
    for name, vaule in _register_modules.items():
        if vaule['elapsed'] == 0:
            continue
        module_list.append(dict(name=name, elapsed=vaule['elapsed'], calls=vaule['calls']))
    module_list.sort(key=lambda x: x['elapsed'], reverse=True)

    unit = unit.lower()
    print(20*'-'+' Module Runtime Analysis '+20*'-')
    if start_time is not None or end_time is not None:
        total_runtime = int((end_time - start_time).total_seconds() * 10**6)
        if unit == "h":
            print_total_runtime = total_runtime / 10**6 / 3600
        elif unit == "min":
            print_total_runtime = total_runtime / 10**6 / 60
        elif unit == "s":
            print_total_runtime = total_runtime / 10**6
        elif unit == "ms":
            print_total_runtime = total_runtime / 10**3
        else:
            print_total_runtime = total_runtime
        
        if unit == "us":
            print(f'Total runtime: {print_total_runtime} {unit}')
        else:
            print(f'Total runtime: {print_total_runtime:.3f} {unit}')

        table = PrettyTable(["index", "module", f"elapsed ({unit})", "calls", f"avg_runtime ({unit})", "percentage (%)"])
        for i, m in enumerate(module_list):
            avg_runtime = m['elapsed'] / m['calls']
            percentage = m['elapsed'] / total_runtime * 100
            if unit == "h":
                print_elapsed = m['elapsed'] / 10**6 / 3600
                print_avg_runtime = avg_runtime / 10**6 / 3600
            elif unit == "min":
                print_elapsed = m['elapsed'] / 10**6 / 60
                print_avg_runtime = avg_runtime / 10**6 / 60
            elif unit == "s":
                print_elapsed = m['elapsed'] / 10**6
                print_avg_runtime = avg_runtime / 10**6
            elif unit == "ms":
                print_elapsed = m['elapsed'] / 10**3
                print_avg_runtime = avg_runtime / 10**3
            else:
                print_elapsed = m['elapsed']
                print_avg_runtime = avg_runtime
            
            if unit == "us":
                table.add_row([str(i+1), m["name"], str(print_elapsed), str(m["calls"]), str(print_avg_runtime), f'{percentage:.2f}'])
            else:
                table.add_row([str(i+1), m["name"], f"{print_elapsed:.3f}", str(m["calls"]), f"{print_avg_runtime:.3f}", f'{percentage:.2f}'])
        print(table)
    else:
        table = PrettyTable(["index", "module", f"elapsed ({unit})", "calls", f"avg_runtime ({unit})"])
        for i, m in enumerate(module_list):
            avg_runtime = m['elapsed'] / m['calls']
            if unit == "s":
                print_elapsed = m['elapsed'] / 10**6
                print_avg_runtime = avg_runtime / 10**6
            elif unit == "ms":
                print_elapsed = m['elapsed'] / 10**3
                print_avg_runtime = avg_runtime / 10**3
            else:
                print_elapsed = m['elapsed']
                print_avg_runtime = avg_runtime
            
            if unit == "us":
                table.add_row([str(i+1), m["name"], str(print_elapsed), str(m["calls"]), str(print_avg_runtime)])
            else:
                table.add_row([str(i+1), m["name"], f"{print_elapsed:.3f}", str(m["calls"]), f"{print_avg_runtime:.3f}"])
        print(table)
