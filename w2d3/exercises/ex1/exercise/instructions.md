# Flower Power: New Version Package Attack Exercise

## Context Story

Once upon a time, in a small town, there was a cheerful flower shop called "Flower Power." The shop was famous for its vibrant bouquets and friendly service. To keep up with the times, the owner decided to use a custom software package called `flower-power` to manage inventory and display flowers on their website.

### What You'll Learn
How to hack a website?(if I tell you it will ruin the exercise)

## How to Run
0. **Don't read the source code!** Don't use a LLM for help!

1. Run

   ```sh
   docker compose up -d # If this doesn't work, try running it outside the dev container, then return to working inside the dev container.
   ```

2. Open your browser and go to `http://localhost:5000`

If you need a rebuild(you are not supposed to need one)

   ```sh
   DOCKER_BUILDKIT=0 docker compose build --no-cache
   docker compose up -d
   ```

3. **Stop and clean up**

   ```sh
   docker compose down -v --remove-orphans
   ```

### Notes

- If you see "failed to find target default" during build, run the rebuild command above with `DOCKER_BUILDKIT=0`.



## After this
Go to exercies/ex2/exercie/instructions.md
