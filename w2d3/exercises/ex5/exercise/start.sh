#!/bin/bash

echo "Starting Snake Game Exercise..."
echo "Building and starting the containers..."

docker-compose up --build -d

echo ""
echo "🎮 Snake Game is starting up!"
echo "📱 Open your browser and go to: http://localhost:5000"
echo ""
echo "🎯 Your mission: Become the leaderboard champion!"
echo "🍎 You are an apple eating snakes to grow your tree"
echo "📥 Download game states and analyze them"
echo "🔧 Create your own pickle files to manipulate the game"
echo ""
echo "💡 Hint: The current champion has a score of 1,000,000"
echo "🚨 Security lesson: Never trust pickle files from untrusted sources!"
echo ""
echo "To stop the game: docker-compose down"
