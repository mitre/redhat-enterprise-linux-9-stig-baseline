#!/bin/bash

# Set the script to exit immediately on error
set -e

# Get the current date and time
backup_date=$(date +%Y%m%d%H%M%S)

# Define the control list file
control_list_file="control_list.txt"

# Check if the control list file exists
if [ -f "$control_list_file" ]; then
  # If it exists, create a backup with a date stamp
  cp "$control_list_file" "${control_list_file}.bak.$backup_date"
fi

# Recreate the control list file
echo "Recreating $control_list_file..."

# Use find and basename to get the list of control files
find ../controls -name '*.rb' -exec basename -s .rb {} \; > "$control_list_file"