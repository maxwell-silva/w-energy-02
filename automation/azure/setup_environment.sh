#!/bin/bash

# Define the project directory based on the script's location.
PROJECT_DIR="$(dirname "$(realpath "$0")")"

# Define the path for the virtual environment.
VENV_DIR="$PROJECT_DIR/venv"

# Check if the virtual environment directory exists.
if [ ! -d "$VENV_DIR" ]; then
    echo "No virtual environment found. Creating one now..."
    # Create a virtual environment in the project directory.
    python3 -m venv $VENV_DIR
fi

# Activate the virtual environment
echo "Activating the virtual environment..."
source $VENV_DIR/bin/activate
echo "Virtual environment activated."

# Now you can safely install Python packages using pip within the environment
echo "Installing required Python packages..."
pip install -r requirements.txt  # Assuming you have a requirements.txt

echo "Environment configured and ready for use!"

# source ./venv/bin/activate