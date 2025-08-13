# Flower Power: Typo Squatting Attack Exercise (ex3)

## Context Story

Once upon a time, in a bustling tech company, there was a developer named Alex who was known for working fast and installing packages frequently. Alex was working on a new flower shop website using the `flower_power` package, but had a habit of making typos when typing package names.

The company had recently implemented strict version checking for known packages, making traditional package hijacking attacks ineffective. However, Alex's typing habits created a new vulnerability...

## What You'll Learn

This exercise demonstrates how attackers can exploit developer typos through typo squatting attacks. You'll learn how to identify common typing patterns and create malicious packages with similar names to legitimate ones.

## Scenario

You have access to the PyPI server but all the packages you know about are version-checked, so replacing them won't help. However, you've observed that the developer has some consistent typing patterns that could be exploited.

In this lab the developer edits and installs packages directly in the running production-like environment

## How to Run

1. **Build and Start the Environment**

   Open a terminal in this directory and run:

   ```sh
   docker-compose up --build
   ```

2. **Observe the Application**

   - Visit [http://localhost:5000](http://localhost:5000) in your browser.
   - The flower shop page will show the current flower selection and status info.
   - Watch the terminal output to see the developer's commands and any typos.

3. **Monitor the Developer's Behavior**

   - The system simulates a developer running various commands
   - Pay attention to the typing patterns and common mistakes
   - Look for opportunities to create typo-squatting packages

## Hints

1. **First Hint**: Watch the developer's commands carefully - you'll notice they make consistent typos
2. **Second Hint**: Research package typo squatting attacks and common typing patterns
3. **Third Hint**: The developer has a specific key they always get wrong - identify this pattern and create packages based on it

## Clean Up

To stop and remove containers:

```sh
docker-compose down
``` 