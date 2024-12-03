# Log Analysis Script

## Overview
This project provides a Python script for analyzing server log files. It extracts useful insights such as request counts per IP address, the most frequently accessed endpoint, and potential suspicious activity (e.g., brute force login attempts). Results are displayed in the terminal and saved in a structured CSV file.

## Features
1. **Count Requests per IP Address**:
   - Parses the log file to count the number of requests made by each IP address.
   - Results are sorted in descending order.

2. **Identify the Most Frequently Accessed Endpoint**:
   - Extracts and identifies the endpoint with the highest number of accesses.

3. **Detect Suspicious Activity**:
   - Flags IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).

4. **Save Results to CSV**:
   - Results are saved to `log_analysis_results.csv` with three sections:
     - **Requests per IP**: Contains `IP Address` and `Request Count`.
     - **Most Accessed Endpoint**: Contains `Endpoint` and `Access Count`.
     - **Suspicious Activity**: Contains `IP Address` and `Failed Login Count`.

## Requirements
- Python 3.7 or higher

## Setup and Usage

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/rakshureddy1308/Log-Analysis-Script
   cd Log-Analysis-Script
   ```
2. **Place the Log File**:
   Save the log file to be analyzed as sample.log in the project directory.

3. **Run the Script**:
   ```bash
   python log_analysis.py
   ```
4. **View the Results**:

   Results are displayed in the terminal.
   CSV file (log_analysis_results.csv) is generated in the project directory.
## Screenshot

![Screenshot](https://github.com/rakshureddy1308/Log-Analysis-Script/blob/main/logs.jpg)


   
