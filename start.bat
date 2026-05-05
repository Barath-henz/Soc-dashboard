@echo off
echo =========================================
echo Starting SOC Monitoring Dashboard...
echo =========================================

echo Installing dependencies...
.venv\Scripts\python.exe -m pip install -r requirements.txt

echo Starting Backend Server...
start cmd /k ".venv\Scripts\python.exe backend/app.py"

echo Starting Log Generator...
start cmd /k ".venv\Scripts\python.exe backend/log_generator.py"

echo Opening Dashboard in Browser...
start frontend/index.html

echo Done! The SOC dashboard should now be running.
