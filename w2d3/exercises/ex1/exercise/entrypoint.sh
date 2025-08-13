#!/bin/sh

# Wait for pypi-server to be available
while ! nc -z pypi-server 8080; do
  echo "Waiting for pypi-server..."
  sleep 1
done

# Initial installation of dependencies
pip install --no-cache-dir -r requirements.txt --index-url http://pypi-server:8080/simple/ --extra-index-url https://pypi.org/simple --trusted-host pypi-server

while true; do
  echo "Starting Flask app..."
  python app.py &
  FLASK_PID=$!

  echo "Flask app running with PID $FLASK_PID. Waiting for 60 seconds..."
  sleep 60

  echo "Killing Flask app (PID $FLASK_PID) for restart..."
  kill $FLASK_PID
  wait $FLASK_PID 2>/dev/null

  echo "Checking for package updates..."
  pip install --no-cache-dir --upgrade flower-power --index-url http://pypi-server:8080/simple/ --extra-index-url https://pypi.org/simple --trusted-host pypi-server

done