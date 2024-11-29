from pathlib import Path

ROOT = Path(__file__).parent.parent

import sys
sys.path.append(str(ROOT/"src"))

from mlcbase import ConfigDict


def run():
    data = dict(name="Weiming Chen",
                age=27,
                gender="male",
                school=dict(name="Southern University of Science and Technology", location="Shenzhen"),
                repository=["github", "gitlab", "gitee"])
    data = ConfigDict(data)
    assert data.name == "Weiming Chen"
    assert data.age == 27
    assert data.gender == "male"
    assert isinstance(data.school, ConfigDict)
    assert data.school.name == "Southern University of Science and Technology"
    assert data.school.location == "Shenzhen"
    assert isinstance(data.repository, list)
    assert data.repository[0] == "github"
    assert data.repository[1] == "gitlab"
    assert data.repository[2] == "gitee"


if __name__ == "__main__":
    run()
