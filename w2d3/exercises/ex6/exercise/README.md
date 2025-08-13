# Exercise 5: Snake Game - Apple vs Snakes

## Scenario

A developer has created a cool game for their website! You are an apple going around a map and eating snakes to get faster and faster. All snakes are the same size and eating one increases the apple tree by one. When you hit one of the walls, you fail. The apple is always one game pixel and the snakes are also one game pixel.

The developer wants customers to be able to download their game state and continue playing afterward. They also added a leaderboard of all customers. Your challenge is to become number 1! The current leader created an apple tree with size 1 million (the score is the size of the apple tree - each time you eat a snake this gets increased by one).

## Setup

1. Start the game:
   ```bash
   docker-compose up --build
   ```

2. Open your browser and go to `http://localhost:5000`

3. The game is in a window on the main page of the website

## Attack Objective

Create your own pickle file to manipulate the game state and become the leaderboard champion!

## Student Steps

1. **Play the game and download the state**
   - Start the game and play for a bit
   - Press SPACEBAR or click "Pause Game" to pause when you want to save
   - Use the "Download State" button to save your current game state
   - Examine the downloaded pickle file

2. **Try loading it and see what happens**
   - Use the "Upload State" button to load your saved state
   - The game will start in paused mode - click "Continue Game" to resume
   - Verify that the game continues from where you left off

3. **Tinker with it and see what happens**
   - Open the pickle file in a text editor (it will look like binary data)
   - Try to understand the structure by downloading multiple states and comparing them

4. **Download a couple different ones and compare them**
   - Play the game multiple times with different scores
   - Download states at different points and compare the files

5. **Create your own changing only the apple position**
   - Use Python to create a custom pickle file
   - Modify the apple position to place it in strategic locations
   - Try to create a state with a very high score

