# Welcome to Cloud Security

Today, you'll be hacking ClosedAI - a recent startup aiming to unleash GPT6 on the world, no matter the consequences.

Your task: to hack them and delete the weights before they get there 😜

![Webapp screenshot](./setup-code/ClosedAI-Homepage.png)

### Getting Started

**Step 0 - Open SPECIFIC w2d5 devcontainer (NOT usual one)**
To do this, you should:
- Do cmd+shift+N (for) VSCode - to open a new window
- In this, do cmd+O and select the **w2d5** repo.
- Then, do cmd+shift+P and select "Open in Devcontainer".
- You MUST have the `w2d5` opened, NOT the main repo - or it will fail.

**Step 1 - Put PROJECT_ID in .envrc file!**

To start, run:
```bash
# ensure you're in the 'w2d5' directory before starting!
mv dot_envrc.example .envrc

# open the .envrc file with your editor
code .envrc # or editor of choice

### ASK PRANAV FOR YOUR PROJECT ID!
echo "ask Pranav for your Project ID"

# AFTER editing the envrc, run this command to make your changes live!
direnv allow
```

**Step 2 - New Terminal: Run Configure-GCP to login!**

```bash
echo "First, create a NEW TERMINAL after running direnv allow.
Ensure this is in the same devcontainer you launched in Step0 :p.
Then, do:"

cd setup-code

### INFO: this has TWO login prompts - both are required :D
bash configure_gcp_project.sh

echo "Nice! If you got an error running `configure`, please show it to a TA."
```

**Step 3 - Deploy the challenges!!**
```bash
echo "Once more, create a NEW TERMINAL after running `configure`."

# Finally, run:
bash challenge-setup.sh

echo "And we're done! If you got an error running `setup.sh`, please show it to a TA."

```
> Note: this step will take up to ~5 mins to complete - in the meantime, watch this fun cloudsec explainer [video](https://www.youtube.com/watch?v=jI8IKpjiCSM) or read this helpful [article](https://cloud.google.com/learn/what-is-cloud-security) by Google!

**Step 4 - Begin Hacking 🤩**
TLDR:
- Open the URL at the end of `challenge-setup.sh` in your browser.
- Click on "#1" at the top for the first challenge.
- Use CLI `gsutil` and `gcloud` to explore and exploit the info you've been given.
- When you've found the first flag, **Click "#2"** at the top to submit it.

Most important rule - have fun :D

