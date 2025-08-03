Welcome to [AI Security Bootcamp](https://www.aisb.dev/) (AISB)! AISB is a 4-week long program to bring researchers and engineers up to speed on security fundamentals for AI systems. This repo contains the exercises and links to the reading material you will go through during the bootcamp.



## Setup
Make sure you have the prerequisites listed below, and open a cloned copy of this repo in your IDE. It is recommended to use a VS Code based IDE with Dev Containers - see [Default setup](#default-setup-vs-code-based-ide-with-dev-containers). For alternative setups, expand the collapsible sections below.


### Prerequisites
1. **Download and install [Docker desktop](https://www.docker.com/products/docker-desktop/)**
2. **Clone this repo**
    - It is recommended that you save your progress (solution files you will create throughout the bootcamp) to a branch in this repo. For that you will need to:
        - Make sure you have [an ssh key](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent#adding-your-ssh-key-to-the-ssh-agent) registered [with your GitHub account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account), and [configured](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent?platform=mac#adding-your-ssh-key-to-the-ssh-agent) in your `.ssh/config` or ssh-agent.
        - You can test this is configured correctly with `ssh -T git@github.com`.
        - Clone the [aisb repo](https://github.com/pranavgade20/aisb)
            ```bash
            git clone git@github.com:pranavgade20/aisb.git
            ```
    - Alternatively, if you don't want to save your progress to a branch or just you just want to get started quickly, clone the repo with

        ```bash
        git clone https://github.com/pranavgade20/aisb.git
        ```

### Default setup: VS Code based IDE with Dev Containers
If using VS Code base IDE, we recommend using the Dev Containers feature. This will start a Docker container with Python and all necessary dependencies already installed that your IDE will connect to. If you execute a file or open a terminal in your IDE, this will be executed inside the container while keeping the user experience of working locally (see more on [how it works](https://code.visualstudio.com/docs/devcontainers/tutorial#_how-it-works)).

- Install [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension
- Open Command Palette (press `F1` or select `View -> Command Palette`) and select `Dev Containers: Open Folder in Container`
- Select the directory with cloned `pranavgade20/aisb` repo.

If you have problems with this setup on Windows, you can check out [these tips](https://code.visualstudio.com/docs/devcontainers/tips-and-tricks#_docker-desktop-for-windows-tips).

<details>
<summary><b>If not using Dev Containers</b></summary>

If for whatever reason you decide _not_ to use Dev Containers, make sure you have the following extensions installed:

- `ms-python.python`
- `ms-python.vscode-pylance`
- `ms-toolsai.jupyter`
- `bierner.markdown-mermaid`

You will also need to set up your Python environment according to [Seting up Python environment without Dev containers](#seting-up-python-environment-without-dev-containers).
</details>

### If using a different IDE
Other IDEs are not officially supported and not recommended. If you decide to use one, you may still [be able to use dev containers](https://www.jetbrains.com/help/pycharm/connect-to-devcontainer.html). Otherwise, set up your Python environment according to [Seting up Python environment without Dev containers](#seting-up-python-environment-without-dev-containers).


### Seting up Python environment without Dev containers
You will only need to do this if you *don't* use the recommended setup with VS Code and Dev Containers.

<details>
<summary>Expand instructions</summary>

For most exercises, you need a Python environment with Python >= 3.11 and the dependencies from `requirements.txt` installed. If an exercise needs a more complicated setup, it will be described in its instructions.

You can set up the Python environment with these steps:

1. [Install miniconda](https://www.anaconda.com/docs/getting-started/miniconda/install#quickstart-install-instructions)
2. Verify conda was installed and activated by running `conda --version`
3. Create and activate a new environment:
    
    ```bash
    conda create --name aisb python=3.11
    conda activate asib
    ```
4. Navigate to this directory and install requirements:

    ```bash
    pip install -r requirements.txt
    ```
5. Make sure that the new conda environment is activated in your IDE. You can get the correct path to Python executable with

    ```bash
    conda run -n aisb which python
    ```

</details>


## In-person instructions
If you're attending the bootcamp in person, you will spend most of the days pair programming with your assigned partner on the exercises for the given day.

On your first day, make sure you have completed the instructions in the [Setup](#setup) section above.


### Completing exercises
To view the instructions for a day, navigate to the respective directory (e.g., `w1d1` for day 1 of week 1) and open the `*_instructions.md` file located there. We recommend you open it in your IDE and view the markdown (right-click and select "Open Preview" in VS Code).

The recommended way to complete the exercises is to make a new `.py` file (suggested name: `w#d#_answers.py`) in the directory for the day. 

The instructions will contain code snippets you need to complete. Add a new `# %%` line to your answers and paste the code snippet under that line. If you went through the setup instructions correctly (with VS Code), you should see "Run Cell" option above the `# %%` which will execute the code in a [Python Interactive Window](https://code.visualstudio.com/docs/python/jupyter-support-py#_jupyter-code-cells). The code snippets contain tests that should initially fail. Complete the TODOs in the code and run the cell until all the tests pass. 

<details>
<summary>Using Python cells</summary>
If you add more code at the bottom of the file and follow it with another `# %%`, this will create another cell which can be run independently in the same session. Cells can be run many times and in any order you choose; the session will maintain variables and state until it is restarted. 
</details>

### Using git
We recommend you save your progress for each day (the answer files you will create with your assigned partner) to a branch in this repo. This will make it possible for you to switch between computers you will use while pair programming, and make your solution available for you to reference later.

First, configure your git repo with:

```bash
git config pull.rebase true
git config --type bool push.autoSetupRemote true
```

**Every day in the morning**, make sure you have the latest version of the repo:
```bash
git checkout master
git pull
```

Make a branch for the day: `git checkout -b <branch name>`, where your branch name should follow the convention `w#d#/<name>-and-<name>`. For example, if Tamera and Edmund were pairing on the week 1 day 3 content, the command would be `git checkout -b w1d3/tamera-and-edmund`. If you share a first name with someone else in the program, use a unique nickname of your choice for disambiguation. 

Create a new file for your answers (see [completing exercises](#completing-exercises) above) and work through the material with your partner. 

As you work, commit changes to your branch and push them to the repo. To make and push a commit:

```bash
git add :/
git commit -m '<your commit message>'
git push
```

If you want to switch what computer you work on with your partner, they can check out the latest version of the branch with:

```bash
git fetch
git checkout <branch name>
git pull
```


### Testing your setup
If you'd like to try a sample exercise and test your setup, go ahead and complete [w1d0](./w1d0/w1d0_instructions.md)!
