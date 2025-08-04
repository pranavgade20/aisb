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


from w1d0_test import test_prerequisites

# Run the prerequisite checks
test_prerequisites()

# %%

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

    Returns:
        The user's name, location, email, and 5 most recently updated repos.
    """
    # Return information about the given GitHub user

    # 1. Make a GET request to: https://api.github.com/users/{username}
    user_response = requests.get(f"https://api.github.com/users/{username}")
    print(user_response.json())
    if user_response.status_code != 200:
        return UserIntel(username=username, name=None, location=None, email=None, repo_names=[])

    # 2. Extract name, location, and email from the response
    user_data = user_response.json()
    name = user_data.get("name")
    location = user_data.get("location")
    email = user_data.get("email")

    # 3. Make another GET request to: https://api.github.com/users/{username}/repos?sort=updated&per_page=5
    user_repos = requests.get(f"https://api.github.com/users/{username}/repos?sort=updated&per_page=5")

    # 4. Extract repository names (limit to 5)
    if user_response.status_code != 200:
        return UserIntel(username=username, name=name, location=location, email=email, repo_names=[])
    repo_names = [repo.get("name") for repo in user_repos.json()]

    # 5. Return a UserIntel object with the gathered information
    return UserIntel(username=username, name=name, location=location, email=email, repo_names=repo_names)


from w1d0_test import test_analyze_user_behavior


test_analyze_user_behavior(analyze_user_behavior)


# %%
