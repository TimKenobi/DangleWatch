#!/bin/bash

# Configuration
VENV_PATH="/opt/certificate_checker/venv"
SCRIPT_PATH="/opt/certificate_checker/certchecker.py"
LOG_FILE="/opt/certificate_checker/output/cron.log"

# Check if virtual environment exists
if [ ! -d "$VENV_PATH" ]; then
    echo "[$(date)] ERROR: Virtual environment not found at $VENV_PATH" >> "$LOG_FILE"
    exit 1
fi

# Check if certchecker.py exists
if [ ! -f "$SCRIPT_PATH" ]; then
    echo "[$(date)] ERROR: certchecker.py not found at $SCRIPT_PATH" >> "$LOG_FILE"
    exit 1
fi

# Activate virtual environment
source "$VENV_PATH/bin/activate"

# Run certchecker.py and redirect output to log
python "$SCRIPT_PATH" >> "$LOG_FILE" 2>&1

# Check exit status
if [ $? -eq 0 ]; then
    echo "[$(date)] Successfully ran certchecker.py" >> "$LOG_FILE"
else
    echo "[$(date)] ERROR: certchecker.py failed with exit code $?" >> "$LOG_FILE"
    exit 1
fi

# Deactivate virtual environment
deactivate
