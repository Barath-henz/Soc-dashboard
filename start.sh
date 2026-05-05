#!/bin/bash

echo "========================================="
echo "Starting SOC Monitoring Dashboard..."
echo "========================================="

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Starting Backend Server..."
python3 backend/app.py &
BACKEND_PID=$!

echo "Starting Log Generator..."
python3 backend/log_generator.py &
LOGGEN_PID=$!

echo "Opening Dashboard in Browser..."
if which xdg-open > /dev/null
then
  xdg-open frontend/index.html
elif which open > /dev/null
then
  open frontend/index.html
fi

echo "Done! The SOC dashboard is now running."
echo "Press Ctrl+C to stop both backend and log generator."

trap "kill $BACKEND_PID $LOGGEN_PID" SIGINT
wait
