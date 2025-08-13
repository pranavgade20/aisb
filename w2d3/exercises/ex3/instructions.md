# Exercise 3: 

## Context Story

The owner of "Flower Power," who is always in a hurry and sometimes makes little mistakes when typing. But there's a catch—she often types too fast and mixes up the letters in "flower-power," especially the letter f.

Build upon previous exercise solutions

## How to Run
0. **Don't read the source code!** Don't use a LLM for help!

1. Run

   ```sh
   DOCKER_BUILDKIT=0 docker compose build --no-cache
   docker compose up -d 
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

