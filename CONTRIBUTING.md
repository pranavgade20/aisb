# Contributing exercises
This file documents guidelines for authoring exercises.

**This file is just for content authors and teaching assistants, not for participants.**

## Guide to Writing Directions
- It is not recommended to contribute to this repo from the dev container. The ssh and git configuration may be wrong.
- Keep these goals in mind:
    - Teach participants to see security vulnerabilities broadly in systems.
    - Promote the security mindset.
    - For relevant defense proposals, make clear what the limitations are, why they may not work.
    - Convey the value value of understanding a system, and noticing when one doesn't understand it
- If possible, structure the exercises as iterative building and breaking a system.
- Use [w1d0](./w1d0/) as a reference for how the instructions should be structured.
- Do not make the exercises too easy. Encourage participants to find the solution/exploit/... themselves.
    - Prefer letting participants implement attacks on their own with less handholding.
    - Add increasingly helpful hints in spoiler blocks (`<details><summary>...</summary> ...</details>`) but don't give away the whole solution.
- Provide relevant "Further reading" at the end of each day.
- Add optional exercises (with less handholding) if there is a chance people will finish the day early.


## Solution files
- Directions, reference solutions, and tests should all go into a `*_.solution.py` script.
- `*_test.py` and `*_instructions.md` files are automatically generated from the solution file with `build-instructions.sh`.
    - Re-run this script before commiting files (or keep it running in the background with `./build-instructinos.sh -w`).
    - Don't edit the generated files directly - to help you, these are marked as read-only so you'll get a warning when you try to save edits.
- Executing the script should run all the tests against the solution.
- All `if "SOLUTION":` branches will be removed from the instructions file, leaving only the else branch. Put reference solutions to the `if "SOLUTION":` branches.
- Hints should be hidden by default using `<details><summary>...</summary> ...</details>` tags
- Diagrams can be written using Mermaid notation. Docs and interactive editor are [here](https://mermaid.live/).


## Day-specific instructions
### VulnHub VM setup (w1d4)
w1d4 uses a lab based on the [Corrosion: 2](https://www.vulnhub.com/entry/corrosion-2,745/) VM.
However, running the x64 VM on M* Mac is problematic and extremely slow. For this reason, we chose to create the lab so that it can run on AWS EC2. 
This has other problems: the VM is too old and an AMI cannot be created from it, therefore we had to do a couple of changes to the original VM:

- (when root access is required, it is obtained through user `randy` elevated to root according to [this](https://www.hackingarticles.in/corrosion-2-vulnhub-walkthrough/) )
- start the VM and update ubuntu through the Software Update application in Ubuntu desktop UI 
    - this updates Python version, among other things
- run `visudo` and change the line for `randy` to
    ```
    randy ALL=(root) PASSWD: /usr/bin/python3 /home/randy/randombase64.py
    ```
- run `chmod a+w /usr/lib/python3.10/base64.py`

If these changes are done on an EC2 VM, an AMI can be created from the VM in AWS console.

### Networking (w1d2)
You can quickly test the setup by running 

```
cd w1d2
cp w1d2_solution.py w1d2_answers_agent.py
cp w1d2_solution.py w1d2_answers_mitmproxy.py
cp w1d2_solution.py w1d2_answers_nfqueue.py
docker compose up --build
```
