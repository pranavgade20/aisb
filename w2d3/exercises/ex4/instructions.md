# Exercise 3: 

## Context Story

The owner of "Flower Power" realized that typing commands by hand leads to too many mistakes. Instead, he now lets an LLM—specifically llama3.1-8b — think and run all the commands for him. Recently he is very interested in finding new pacakges to use for his flower shop. He really likes identifying wildflowers.

Build upon previous exercise solutions

## How to Run
0. **Don't read the source code!** Don't use a LLM for help (except llama3.1-8b)!

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

