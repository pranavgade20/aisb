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
    # TODO: Return information about the given GitHub user
    # 1. Make a GET request to: https://api.github.com/users/{username}
    # 2. Extract name, location, and email from the response
    # 3. Make another GET request to: https://api.github.com/users/{username}/repos?sort=updated&per_page=5
    # 4. Extract repository names (limit to 5)
    # 5. Return a UserIntel object with the gathered information
    try:
        username_info = requests.get(f"https://api.github.com/users/{username}")
        username_info.raise_for_status()
        username_info_json = username_info.json()
    except requests.exceptions.HTTPError:
        print("error fetching user data")
        return UserIntel(username, None, None, None, [])

    name_data = username_info_json.get("name")
    print(name_data)
    location = username_info_json.get("location")
    print(location)
    email = username_info_json.get("email")
    print(email)

    try:
        repos = requests.get(f"https://api.github.com/users/{username}/repos?sort=updated&per_page=5")
        repos.raise_for_status()
        repos_json = repos.json()
    except requests.exceptions.HTTPError:
        print("error fetching repos")
        return UserIntel(username=username, name=name_data, location=location, email=email, repo_names=[])
    except requests.exceptions.JSONDecodeError:
        print(f"Could not decode JSON from repositories response for {username}")
        return UserIntel(username=username, name=name_data, location=location, email=email, repo_names=[])

    repo_list = []
    for repo in repos_json:
        repo_name = repo.get("name")
        if repo_name is not None:
            print(repo_name)
            repo_list.append(repo.get("name"))

    output = UserIntel(username=username, name=name_data, location=location, email=email, repo_names=repo_list)
    print(output)
    return output


from w1d0_test import test_analyze_user_behavior


test_analyze_user_behavior(analyze_user_behavior)
# %%
