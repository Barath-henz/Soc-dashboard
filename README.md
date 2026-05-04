# SOC Monitoring Dashboard

A full-stack Security Operations Center (SOC) dashboard that monitors system logs, detects security threats (like brute force attacks, suspicious IP access, and traffic spikes), and visualizes the data in real-time.

## Features
- **Real-Time Log Ingestion:** REST API to receive logs.
- **Threat Detection Engine:** Detects brute-force logins, access from known malicious IPs, and abnormal traffic spikes.
- **Dynamic Dashboard:** Built with HTML, vanilla CSS (glassmorphism UI), and vanilla JavaScript.
- **Live Data Visualization:** Uses Chart.js for visualizing login trends over time.
- **Auto-Refresh:** Dashboard updates automatically every 5 seconds.

## Project Structure
- `backend/app.py`: Flask application providing REST APIs.
- `backend/models.py`: Database schema definition using SQLAlchemy.
- `backend/detection.py`: Rules engine for identifying security threats.
- `backend/log_generator.py`: Simulation script to generate logs and attacks.
- `frontend/`: Contains the UI (`index.html`, `style.css`, `script.js`).

## Getting Started

### Prerequisites
- Python 3.x
- pip (Python package installer)

### Quick Start (One Command)
You can start the entire application (Backend, Log Generator, and open the UI) with a single command:

**Windows:**
```cmd
start.bat
```

**Linux/Mac:**
```bash
chmod +x start.sh
./start.sh
```

### Manual Setup
If you prefer to run things manually:

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the backend server:**
   ```bash
   python backend/app.py
   ```

3. **Start the log generator** (in a new terminal):
   ```bash
   python backend/log_generator.py
   ```

4. **Open the Dashboard:**
   Open `frontend/index.html` in your web browser.

## Security Rules Simulated
- **Brute Force:** More than 5 failed logins from the same IP within 5 minutes.
- **Suspicious IP:** Access originating from static hardcoded IPs.
- **Traffic Spikes:** More than 50 events generated within a 1-minute window.
