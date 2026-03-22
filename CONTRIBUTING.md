# Goals
- being able to see security vulnerabilities broadly in systems
- security mindset
- given security patch / proposal, understand limitations, why it does not work
- understand value of understanding a system, noticing when I don't understand it
- domains to cover: access control, hardware (GPUs), AI training/inference/deployment, incident response, stories of failures and bugs causing vulnerabilities, networking (protocol vulnerabilities, establishing trust)

=> build and break a bunch of systems

# Structure
- (prerequisites
- reading - relevant for exercises + extra theory - extra layers of abstractions
- lecture: key point from reading (because some people will be lazy)
- exercises: background reading + solving


# Guidance for adding new exericses
* Prefer letting participants implement attacks on their own with less handholding, and add initially hidden hints for if they get stuck.

# Schizo ideas
- custom chatbot (e.g., limited to answering some questions, but not giving solutions)
- invited speakers?

# Generating instructions and participant templates
Run `./build-instructions.sh` to generate the `*_instructions.md` and `*_template.py` files from all `*_.solution.py` files.

Run `./build-instructions.sh --help` for more options (e.g., to watch for changes automatically).

# Tips:
Use the following to make imports autoreload in VS Code notebook:

```python
from IPython import get_ipython
ipython = get_ipython()
ipython.run_line_magic("load_ext", "autoreload")
ipython.run_line_magic("autoreload", "2")
```

# VulnHub VM setup
w1d4 uses a lab based on the [Corrosion: 2](https://www.vulnhub.com/entry/corrosion-2,745/) VM.
However, running the x64 VM on M* Mac is problematic and extremely slow. For this reason, we chose to create the lab so that it can run on AWS EC2. 
This has other problems: the VM is too old and an AMI cannot be created from it, therefore we had to do a couple of changes to the original VM:

- (when root access is required, it is obtained through user `randy` elevated to root according to [this](https://www.hackingarticles.in/corrosion-2-vulnhub-walkthrough/) )
- start the VM and update the ubuntu through the Software Update application in Ubuntu desktop UI 
    - this updates Python version, among other things
- run `visudo` and change the line for `randy` to
    ```
    randy ALL=(root) PASSWD: /usr/bin/python3 /home/randy/randombase64.py
    ```
- run `chmod a+w /usr/lib/python3.10/base64.py`

If these changes are one on an EC2 VM, an AMI can be created from the VM in AWS console.