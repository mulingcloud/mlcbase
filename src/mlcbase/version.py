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
MuLingCloud base module: version control

Author: Weiming Chen
Tester: Weiming Chen, Yuanshaung Sun
"""
import re
from datetime import datetime
from typing import Union


class Version:
    """Version specification
    The version pattern of MuLingCloud modules and applications is: {epoch}.{major}.{minor}.{state}.{date}

    Params:
        epoch (required): An epoch version will be released when a new framework is coming.
        major (required): A major version will be released when there is a major update.
        minor (required): A minor version will be released when there is a minor update
        state (required): The state of the module or application. Available values: 
                          dev, alpha, beta, rc{num}, release, where the number of rc
                          is optional.
        date  (optional): The date version. The pattern is YYYYMM.

    Example:
        1.1.0.dev.202404
        1.1.0.alpha
        1.1.0.beta
        1.1.0.rc1.202405
        1.1.0.release
    """
    
    VERSION_PATTERN = r"^(?P<epoch>\d+)\.(?P<major>\d+)\.(?P<minor>\d+)\." \
                      r"(?P<state>dev|alpha|beta|rc(?P<rc_number>\d+)?|release)" \
                      r"(?:\.(?P<date>((?P<year>\d{4})(?P<month>\d{2}))))?$"

    def __init__(self, verison: str):
        self.__pattern = re.compile(self.VERSION_PATTERN)
        if not self.__pattern.match(verison):
            raise ValueError(f"Invalid version format: {verison}")
        
        if self.__pattern.match(verison).group("date"):
            try:
                datetime(year=int(self.__pattern.match(verison).group("year")), 
                         month=int(self.__pattern.match(verison).group("month")), 
                         day=1)
            except ValueError:
                raise ValueError(f"Invalid date format: {self.__pattern.match(verison).group('date')}")
        
        self.__match = self.__pattern.match(verison)

    @property
    def epoch(self) -> int:
        return int(self.__match.group("epoch"))
    
    @property
    def major(self) -> int:
        return int(self.__match.group("major"))
    
    @property
    def minor(self) -> int:
        return int(self.__match.group("minor"))
    
    @property
    def state(self) -> str:
        return self.__match.group("state")
    
    @property
    def state_number(self) -> Union[int, float]:
        if self.state == "dev":
            return 1
        
        if self.state == "alpha":
            return 2
        
        if self.state == "beta":
            return 3
        
        if self.state.startswith("rc"):
            num = 4
            if self.__match.group("rc_number"):
                rc_number = self.__match.group("rc_number")
                num += int(rc_number) / (10**len(rc_number))
            return num
        
        if self.state == "release":
            return 5
    
    @property
    def date(self) -> str:
        return self.__match.group("date")
    
    @property
    def year(self) -> int:
        year = self.__match.group("year")
        return int(year) if year else None
    
    @property
    def month(self) -> int:
        month = self.__match.group("month")
        return int(month) if month else None
    
    def __eq__(self, other: "Version") -> bool:
        """equal

        Args:
            other (Version)

        Returns:
            bool: True if this version equals to the other version, False otherwise.
        """
        if not isinstance(other, Version):
            raise TypeError(f"Unsupported operand type(s) for ==: '{type(self).__name__}' and '{type(other).__name__}'")
        
        if self.__str__() == other.__str__():
            return True
        
        return False
    
    def __ne__(self, other: "Version") -> bool:
        """not equal

        Args:
            other (Version)

        Returns:
            bool: True if this version does not equal to the other version, False otherwise.
        """
        if not isinstance(other, Version):
            raise TypeError(f"Unsupported operand type(s) for !=: '{type(self).__name__}' and '{type(other).__name__}'")
        
        if self.__str__() != other.__str__():
            return True
        
        return False
    
    def __lt__(self, other: "Version") -> bool:
        """less than

        Args:
            other (Version)

        Returns:
            bool: True if this version is less than the other version, False otherwise.
        """
        if not isinstance(other, Version):
            raise TypeError(f"Unsupported operand type(s) for <: '{type(self).__name__}' and '{type(other).__name__}'")
        
        if self.epoch != other.epoch:
            return self.epoch < other.epoch
        
        if self.major != other.major:
            return self.major < other.major
        
        if self.minor != other.minor:
            return self.minor < other.minor
        
        if self.state != other.state:
            return self.state_number < other.state_number
        
        if self.date != other.date:
            return int(self.date) < int(other.date)
        
        return False
    
    def __le__(self, other: "Version") -> bool:
        """less than or equal

        Args:
            other (Version)

        Returns:
            bool: True if this version is less than or equal to the other version, False otherwise.
        """
        if not isinstance(other, Version):
            raise TypeError(f"Unsupported operand type(s) for <=: '{type(self).__name__}' and '{type(other).__name__}'")
        
        if self.epoch != other.epoch:
            return self.epoch < other.epoch
        
        if self.major != other.major:
            return self.major < other.major
        
        if self.minor != other.minor:
            return self.minor < other.minor
        
        if self.state != other.state:
            return self.state_number < other.state_number
        
        if self.date != other.date:
            return int(self.date) <= int(other.date)
        
        return True
    
    def __gt__(self, other: "Version") -> bool:
        """greater than

        Args:
            other (Version)

        Returns:
            bool: True if this version is greater than the other version, False otherwise.
        """
        if not isinstance(other, Version):
            raise TypeError(f"Unsupported operand type(s) for >: '{type(self).__name__}' and '{type(other).__name__}'")
        
        if self.epoch != other.epoch:
            return self.epoch > other.epoch
        
        if self.major != other.major:
            return self.major > other.major
        
        if self.minor != other.minor:
            return self.minor > other.minor
        
        if self.state != other.state:
            return self.state_number > other.state_number
        
        if self.date != other.date:
            return int(self.date) > int(other.date)
        
        return False
    
    def __ge__(self, other: "Version") -> bool:
        """greater than or equal

        Args:
            other (Version)

        Returns:
            bool: True if this version is greater than or equal to the other version, False otherwise.
        """
        if not isinstance(other, Version):
            raise TypeError(f"Unsupported operand type(s) for >=: '{type(self).__name__}' and '{type(other).__name__}'")
        
        if self.epoch != other.epoch:
            return self.epoch > other.epoch
        
        if self.major != other.major:
            return self.major > other.major
        
        if self.minor != other.minor:
            return self.minor > other.minor
        
        if self.state != other.state:
            return self.state_number > other.state_number
        
        if self.date != other.date:
            return int(self.date) > int(other.date)
        
        return True
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.__str__()})"

    def __str__(self) -> str:
        return self.__match.group()
