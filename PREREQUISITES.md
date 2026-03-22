### Overview

This bootcamp is intensive and fast-paced. We cover AI security topics assuming you're already comfortable with foundational tools and concepts. **The bootcamp does not teach programming, command-line basics, or ML fundamentals** — you're expected to arrive with these skills already in place.

If you're unsure whether you're ready, use the self-assessment tests below. If you can answer most questions confidently and complete the practical exercises without significant struggle, you're good to go. If not, invest time in the learning resources before the bootcamp starts.

### ✅ Required Prerequisites

<details open>
<summary><b>🖥️ VS Code or Similar IDE</b></summary>

**Why this matters**: You'll use an IDE with Jupyter notebook support to run Python cells, debug code, and view markdown instructions.

**Minimum competency**:
- Open and navigate projects
- Run Python files and interactive cells (`# %%`)
- Use the integrated terminal
- Install and manage extensions
- Configure Python interpreters (select the right virtual environment)

**Self-test**:
- Can you open a folder, create a `.py` file, add a `# %%` cell, and run it?
- Do you know how to select a Python interpreter from your virtual environment?
- Can you use the built-in terminal and switch between multiple terminals?

**Resources**:
- [VS Code Python tutorial](https://code.visualstudio.com/docs/python/python-tutorial)
- Familiarize yourself especially with the [Python Interactive Window](https://code.visualstudio.com/docs/python/jupyter-support-py) feature of VS Code
- It's very good to learn and internalize keyboard shortcuts for quickly navigating VS Code.
</details>

<details open>
<summary><b>🐍 Python</b></summary>

**Why this matters**: All exercises are in Python. You'll write and debug code daily, use libraries like `requests`, `cryptography`, and PyTorch, and work with virtual environments.

**Minimum competency**:
- Write functions, classes, and use common data structures (lists, dicts, sets)
- Know how to [install packages with pip](https://realpython.com/what-is-pip/) and manage virtual environments (`venv` or `conda`)
- Import and use standard libraries (`os`, `sys`, `json`, `base64`, `hashlib`)
- [Basic usage](https://requests.readthedocs.io/en/latest/user/quickstart/) of the [requests](https://pypi.org/project/requests/) library
- Read and understand error messages and stack traces
- Debug code using print statements or a debugger

**Self-test**: 
- Can you write a function that reads a JSON file, processes the data (e.g., filter, transform), and writes results to a new file?
- Can you create a virtual environment, install packages from `requirements.txt`, and activate it in your IDE?
- Can you explain what `import` does and the difference between `from module import function` vs `import module`?
- Can you decode base64-encoded data and compute a SHA-256 hash?

**Resources**:
- **Start here**: [Python official tutorial](https://docs.python.org/3/tutorial/) (sections 3-9)
- How to create and use virtual environments, at least to the degree described by the first two sections ("How Can You Work With a Python Virtual Environment?", "How Do You Enable a Venv in Your IDE?") from this [primer from Real Python](https://realpython.com/python-virtual-environments-a-primer/)
- Practice: Solve [easy LeetCode problems](https://leetcode.com/problemset/?difficulty=EASY) and try to solve them increasingly quickly

</details>

<details open>
<summary><b>🌐 Networking Fundamentals</b></summary>

**Why this matters**: Week 1 includes packet analysis, TLS/SSL interception, and web security. You'll need to understand how data travels across networks and the HTTP protocol.

**Minimum competency**:
- Explain the OSI model layers and why they matter for security
- Understand TCP vs UDP, IP addresses, ports, and DNS
- Know how HTTP/HTTPS works (requests, responses, headers, status codes)
- Understand what happens when you visit a website (DNS lookup, TCP handshake, TLS negotiation)
- Recognize common protocols (SSH, HTTP, DNS) and their default ports

**Self-test**:
- Can you explain the difference between TCP and UDP, and when each is used?
- What happens when you type a URL in your browser? (Describe the full flow: DNS → TCP → TLS → HTTP)
- What are HTTP status codes? Name 5 common ones (e.g., 200, 404, 500) and what they mean.
- Why does HTTPS matter for security? What does TLS provide?

**Resources**:
- **Essential**: [Networking fundamentals by Practical Networking](https://www.practicalnetworking.net/series/networking-fundamentals/networking-fundamentals/) (Chapters 1-3)
- **Essential**: [MDN HTTP Overview](https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview) 
- [MDN Session](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Session)
- [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)
- [MDN HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP)
- Optional deep dive: [Computer Networking: A Top-Down Approach](https://gaia.cs.umass.edu/kurose_ross/online_lectures.htm)

</details>

<details open>
<summary><b>🔧 Git & Version Control</b></summary>

**Why this matters**: You'll commit your work daily, collaborate with a partner, switch between branches, and pull updates from the main repository.

**Minimum competency**:
- Clone a repository
- Create branches and switch between them
- Stage changes, commit with meaningful messages, and push to remote
- Pull changes and handle basic merge conflicts
- Understand what `.gitignore` does

**Self-test** - You can skip this if you feel comfortable with:
- Cloning a repository
- Pulling new changes
- Creating and switching between branches
- Committing changes
- Pushing branches

**Resources**:
- [An Intro to Git and GitHub for Beginners](https://product.hubspot.com/blog/git-and-github-tutorial-for-beginners)
- Alternatively, you may find this [git cheat sheet](https://education.github.com/git-cheat-sheet-education.pdf) helpful

</details>

<details open>
<summary><b>💻 Bash & Command Line</b></summary>

**Why this matters**: You'll run scripts, navigate file systems, use SSH, manage processes, and work with Docker from the command line.

**Minimum competency**:
- Navigate directories (`cd`, `ls`, `pwd`)
- Create, move, copy, and delete files (`touch`, `mkdir`, `cp`, `mv`, `rm`)
- View file contents (`cat`, `less`, `head`, `tail`)
- Use pipes (`|`), redirection (`>`, `>>`), and grep for searching
- Understand file permissions and use `chmod`
- Use SSH to connect to remote servers
- Run processes in the background and use `ps`, `kill`
- Know how to use the following command line tools: `sudo`, `ssh`, `curl`, `find`, `apt`

**Self-test**:
- Can you find all `.py` files in a directory tree containing the word "test"? (Hint: `find` + `grep`)
- How do you check if a port (e.g., 8080) is in use?
- What's the difference between `sudo` and running as root?
- How do you monitor resource usage (CPU, memory) of a process?
- Can you explain what `curl` does and use it to make an HTTP request?

**Resources**:
- You should be familiar with the [basics of bash scripting](https://www.freecodecamp.org/news/bash-scripting-tutorial-linux-shell-script-and-command-line-for-beginners/) and everything in this [basic bash cheat sheet](https://www.datacamp.com/cheat-sheet/bash-and-zsh-shell-terminal-basics-cheat-sheet)
- Read through [this primer](https://gist.github.com/feynmanix/a60bba4c6593ef3949dfe615f0979c04) for the essential command line tools
- You may also find this [advanced cheat sheet](https://devhints.io/bash) useful
- We strongly recommend reading up on bash best practices, e.g., [here](https://sap1ens.com/blog/2017/07/01/bash-scripting-best-practices/). Following them can help you prevent many bugs that are hard to troubleshoot (e.g., unexpected variable expansions if you don't use quotes around command line arguments)
- Optional hands-on practice: [OverTheWire: Bandit](https://overthewire.org/wargames/bandit/) capture the flag game (levels 1-13)
- **Test your skills**: [Shell usage sample exercise](https://gist.github.com/feynmanix/d1c5502a8c7cd3dc070905b907669fa3)

</details>

<details open>
<summary><b>🐳 Docker</b></summary>

**Why this matters**: Week 1-2 exercises run in Docker containers. You'll build images, run containers, manage volumes, and understand isolation.

**Minimum competency**:
- Understand what containers are and why they're used
- Pull images and run containers (`docker pull`, `docker run`)
- List running containers and stop them (`docker ps`, `docker stop`)
- Understand basic `Dockerfile` syntax (FROM, RUN, COPY, CMD)
- Use Docker Compose to run multi-container applications
- Map ports and volumes between host and container

**Self-test**:
- Can you explain the difference between an image and a container?
- How do you run a container in detached mode and view its logs?
- What's the purpose of port mapping (e.g., `-p 8080:80`)?
- How do volumes work, and why would you use them?
- Can you write a simple `Dockerfile` that installs Python dependencies and runs a script?

**Resources**:
- [Docker overview](https://docs.docker.com/get-started/docker-overview/)
- [Docker Compose tutorial](https://docs.docker.com/compose/intro/compose-application-model/)
- [Docker cheat sheet](https://dockerlabs.collabnix.com/docker/cheatsheet/)

</details>

<details open>
<summary><b>🤖 PyTorch Basics</b></summary>

**Why this matters**: Week 3 focuses on AI security, including model extraction, adversarial attacks, and prompt injection. You'll work with neural networks, tensors, and training loops.

**Minimum competency**:
- Understand what tensors are and basic operations (reshape, indexing, matrix multiplication)
- Know how to define a model using `nn.Module`
- Understand forward passes, loss functions, and backpropagation
- Load pre-trained models and run inference
- Move models and data between CPU and GPU
- Save and load model weights

**Self-test** - You can skip the tutorial if you can clearly explain:
- How to [install](https://pytorch.org/get-started/locally/) PyTorch?
- At a high level, what is a `torch.Tensor`?
- What do we gain by making a class a subclass of `nn.Module`?
- What is a `nn.Parameter`? When should you use one?
- How are models saved and loaded?
- When you call `backward()`, where are your gradients stored?
- What is a loss function? In general, what does it take for arguments, and what does it return?
- What does an optimization algorithm do?
- What is a hyperparameter, and how does it differ from a regular parameter?

**Resources**:
- **Start here**: [Learn the Basics](https://pytorch.org/tutorials/beginner/basics/intro.html) - a seven step beginner introduction to PyTorch
- You can also gauge where you have gaps by going through this [PyTorch cheat sheet](https://www.datacamp.com/cheat-sheet/deep-learning-with-py-torch). Another alternative as a refresher is the [Learning PyTorch with Examples](https://pytorch.org/tutorials/beginner/pytorch_with_examples.html) tutorial
- It is also useful to understand how [saving and loading models](https://pytorch.org/tutorials/beginner/saving_loading_models.html) in PyTorch works

</details>

### Optional Prerequisites

These skills will **enhance your experience** but aren't strictly required. You can learn them during the bootcamp if needed but it's good to be familiar with them beforehand.

<details>
<summary><b>🔍 Packet Analysis (Wireshark)</b></summary>

**Why this matters**: Week 1 Day 2 includes packet capture and analysis exercises.

**What you'll learn**: How to capture network traffic, filter packets, and inspect protocol details.

**Resources**:
- [Wireshark tutorial](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Wireshark display filters](https://wiki.wireshark.org/DisplayFilters)

</details>

<details>
<summary><b>🏗️ Transformers & LLMs</b></summary>

**Why this matters**: Week 3 includes LLM-specific attacks (prompt injection, jailbreaks). Understanding attention mechanisms and tokenization helps. The bootcamp covers this, but prior familiarity accelerates learning.

**Resources**:
- [Illustrated Transformer](https://jalammar.github.io/illustrated-transformer/)
- [3Blue1Brown on neural networks](https://www.3blue1brown.com/topics/neural-networks) - Overview and general understanding of neural networks
- We recommend you go through chapters [0.0-0.4 of ARENA](https://arena-chapter0-fundamentals.streamlit.app/). This will also give you an idea of what AI Security Bootcamp exercises look like - they are structured similarly to an earlier version of ARENA

</details>

<details>
<summary><b>📚 AI Safety Fundamentals</b></summary>

**Why this matters**: Understanding the broader AI safety landscape provides useful context for security work.

**What you'll learn**: Alignment, robustness, interpretability, and long-term risks.

**Resources**:
- [AI Safety Fundamentals textbook](https://ai-safety-atlas.com/chapters)
- [AGI Safety Fundamentals course](https://www.agisafetyfundamentals.com/)

</details>

### 🧪 Complete Setup Test

<details open>
<summary>Complete Setup Test</summary>

Before the bootcamp starts, verify your entire setup works:

**Step 1**: Create a Python virtual environment
```bash
python -m venv aisb-test
source aisb-test/bin/activate  # On Windows: aisb-test\Scripts\activate
```

**Step 2**: Install PyTorch
```bash
pip install torch torchvision
```

**Step 3**: Open VS Code, create `test.py`, and write a [basic PyTorch training loop](https://pytorch.org/tutorials/beginner/basics/optimization_tutorial.html) on MNIST using Python cells (`# %%`)

**Step 4**: Run the cell and verify it trains

**Step 5**: Commit and push to a test Git repository
```bash
git init
git add test.py
git commit -m "Test setup"
git remote add origin <your-repo-url>
git push -u origin main
```

**Step 6**: Pull a Docker image and run a container
```bash
docker pull python:3.12
docker run -it python:3.12 python -c "print('Docker works!')"
```

If all steps complete without errors, you're ready! 🎉
</details>

### 📊 Self-Assessment Summary

<details open>
<summary>Self-Assessment Summary</summary>

Use this checklist to gauge your readiness:

- [ ] I can write and debug Python code with confidence
- [ ] I understand networking concepts (TCP/IP, HTTP, DNS, TLS)
- [ ] I can use Git for version control (commit, push, branches)
- [ ] I'm comfortable with the command line (bash, file operations, SSH)
- [ ] I can run Docker containers and understand basic containerization
- [ ] I can work with PyTorch (tensors, models, training loops)
- [ ] I have VS Code (or similar IDE) set up with Python support
</details>

### Setup
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
- In the VS Code IDE, open Command Palette (press `F1` or select `View -> Command Palette`) and select `Dev Containers: Open Folder in Container`
- Select the directory with cloned `pranavgade20/aisb` repo.

If you have problems with this setup on Windows, you can check out [these tips](https://code.visualstudio.com/docs/devcontainers/tips-and-tricks#_docker-desktop-for-windows-tips).

<details open>
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

<details open>
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