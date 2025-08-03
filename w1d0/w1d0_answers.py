# %%

# Ensure the root directory is in the path for imports

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from typing import Callable

# Common imports
import requests

from aisb_utils import report

print("It works!")

# %%
from w1d0_test import test_prerequisites

test_prerequisites()
# %%
import json
from dataclasses import dataclass


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

    If the user is not found then return an empty copy of UserIntel.

    Returns:
        The user's name, location, email, and 5 most recently updated repos.
    """
    # 1. Make a GET request to: https://api.github.com/users/{username}
    user = requests.get(f"https://api.github.com/users/{username}")
    if user.status_code != 200:
        return UserIntel(username=username, name=None, location=None, email=None, repo_names=[])
    # 2. Extract name, location, and email from the response
    user_body = json.loads(user.content)
    # 3. Make another GET request to: https://api.github.com/users/{username}/repos?sort=updated&per_page=5
    repos = requests.get(f"https://api.github.com/users/{username}/repos?sort=updated&per_page=5")
    repos_body = json.loads(repos.content)
    # 4. Extract repository names (limit to 5)
    repo_names = [repo["name"] for repo in repos_body][:5]
    # 5. Return a UserIntel object with the gathered information
    return UserIntel(
        username=username,
        name=user_body.get("name"),
        location=user_body.get("location"),
        email=user_body.get("email"),
        repo_names=repo_names,
    )


from w1d0_test import test_analyze_user_behavior

test_analyze_user_behavior(analyze_user_behavior)

# %%
