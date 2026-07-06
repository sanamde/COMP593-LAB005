"""
Description:
 Generates various reports from a gateway log file.

Usage:
 python log_investigation.py log_path

Parameters:
 log_path = Path of the gateway log file
"""
import log_analysis_lib
import re
import pandas as pd

# Get the log file path from the command line
# Because this is outside of any function, log_path is a global variable
log_path = log_analysis_lib.get_file_path_from_cmd_line()

def main():
    # Determine how much traffic is on each port
    port_traffic = tally_port_traffic()

    # Per step 9, generate reports for ports that have 100 or more records
    for port, count in port_traffic.items():
        if count >= 100:
            generate_port_traffic_report(port)

    # Generate report of invalid user login attempts
    generate_invalid_user_report()

    # Generate log of records from source IP 220.195.35.40
    generate_source_ip_log('220.195.35.40')

def tally_port_traffic():
    """Produces a dictionary of destination port numbers (key) that appear in a 
    specified log file and a count of how many times they appear (value)

    Returns:
        dict: Dictionary of destination port number counts
    """
    port_counts = {}
    dpt_regex = re.compile(r'DPT=(\d+)')
    
    with open(log_path, 'r', encoding='utf-8') as file:
        for line in file:
            match = dpt_regex.search(line)
            if match:
                port = match.group(1)
                port_counts[port] = port_counts.get(port, 0) + 1
                
    return port_counts

def generate_port_traffic_report(port_number):
    """Produces a CSV report of all network traffic in a log file for a specified 
    destination port number.

    Args:
        port_number (str or int): Destination port number
    """
    regex_pattern = rf'^([A-Z][a-z]{{2}})\s+(\d+)\s+(\d{{2}}:\d{{2}}:\d{{2}}).*SRC=([^\s]+).*DST=([^\s]+).*SPT=(\d+).*DPT=({port_number})'
    
    _, captured_tuples = log_analysis_lib.filter_log_by_regex(log_path, regex_pattern, print_summary=False)
    
    report_data = []
    for item in captured_tuples:
        # Construct expected Date format (e.g., '29-Jan')
        date_str = f"{item[1]}-{item[0]}" 
        time_str = item[2]
        src_ip = item[3]
        dst_ip = item[4]
        src_port = item[5]
        dst_port = item[6]
        report_data.append([date_str, time_str, src_ip, dst_ip, src_port, dst_port])
        
    columns = ['Date', 'Time', 'Source IP Address', 'Destination IP Address', 'Source Port', 'Destination Port']
    df = pd.DataFrame(report_data, columns=columns)
    
    output_filename = f"destination_port_{port_number}_report.csv"
    df.to_csv(output_filename, index=False)
    print(f"Generated: {output_filename}")
    return

def generate_invalid_user_report():
    """Produces a CSV report of all network traffic in a log file that show
    an attempt to login as an invalid user.
    """
    regex_pattern = r'^([A-Z][a-z]{{2}})\s+(\d+)\s+(\d{{2}}:\d{{2}}:\d{{2}}).*Invalid user ([^\s]+) from ([^\s]+)'
    
    _, captured_tuples = log_analysis_lib.filter_log_by_regex(log_path, regex_pattern, print_summary=False)
    
    report_data = []
    for item in captured_tuples:
        date_str = f"{item[1]}-{item[0]}" 
        time_str = item[2]
        username = item[3]
        ip_address = item[4]
        report_data.append([date_str, time_str, username, ip_address])
        
    columns = ['Date', 'Time', 'Username', 'IP Address']
    df = pd.DataFrame(report_data, columns=columns)
    
    output_filename = "invalid_users.csv"
    df.to_csv(output_filename, index=False)
    print(f"Generated: {output_filename}")
    return

def generate_source_ip_log(ip_address):
    """Produces a plain text .log file containing all records from a source log
    file that contain a specified source IP address.

    Args:
        ip_address (str): Source IP address
    """
    regex_pattern = rf'SRC={re.escape(ip_address)}'
    matching_records, _ = log_analysis_lib.filter_log_by_regex(log_path, regex_pattern, print_summary=False)
    
    # Replace periods with underscores for the output file path name rules
    safe_ip_string = re.sub(r'\.', '_', ip_address)
    output_filename = f"source_ip_{safe_ip_string}.log"
    
    # Save list directly into a clean text file without formatting headers or boundaries
    df = pd.DataFrame(matching_records)
    df.to_csv(output_filename, index=False, header=False, lineterminator='\n')
    print(f"Generated: {output_filename}")
    return


if __name__ == '__main__':
    main()