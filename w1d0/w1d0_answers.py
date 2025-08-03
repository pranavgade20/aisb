
# %%

# Ensure the root directory is in the path for imports
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from aisb_utils import report

# Common imports
import requests
from typing import Callable

print("It works!")
# %%
from w1d0_test import test_prerequisites


# Run the prerequisite checks
test_prerequisites()
# %%
from dataclasses import dataclass, asdict
import json

@dataclass
class UserIntel:
    username: str
    name: str | None
    location: str | None
    email: str | None
    repo_names: list[str]


def analyze_user_behavior(username: str = "karpathy") -> UserIntel:
    """
    Analyze a user's GitHub activity patterns.
    This is the kind of profiling attackers might do for social engineering.

    Returns:
        The user's name, location, email, and 5 most recently updated repos.
    """
    r = requests.get(f"https://api.github.com/users/{username}")
    if r.status_code != 200:
        return UserIntel(
          username=username,
          name=None,
          location=None,
          email=None,
          repo_names=[]
        )
    
    user_data = r.json()
    repos = []
    r = requests.get(f"https://api.github.com/users/{username}/repos?sort=updated&per_page=5")

    if r.status_code == 200:
      repos_d = r.json()
      repos = [repo['name'] for repo in repos_d[:5]]

    return UserIntel(
      username=username,
      name=user_data.get("name"),
      location=user_data.get("location"),
      email=user_data.get("email"),
      repo_names=repos
    )

from w1d0_test import test_analyze_user_behavior
test_analyze_user_behavior(analyze_user_behavior)
# %%
