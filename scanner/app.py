from flask import Flask, render_template, jsonify, request
import threading
import socket
import time

app = Flask(__name__)

# Global variables to store scan results and completion status
scan_results = []
scan_complete = False
scan_lock = threading.Lock()  # Lock for thread safety

# Function to scan a range of ports on a target IP with a specified timeout
def scan_ports(target_ip, start_port, end_port):
    global scan_results
    open_ports = []

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set timeout for the connection to avoid hanging
        try:
            result = sock.connect_ex((target_ip, port))  # Try connecting to the target IP and port
            if result == 0:  # If port is open, add it to the list
                open_ports.append(port)
        except socket.error:
            pass
        finally:
            sock.close()  # Close the socket whether the connection succeeded or failed

    with scan_lock:
        scan_results.extend(open_ports)  # Safely append results to the shared list

# Function to handle port scanning in a separate thread
def start_scanning(target_ip, start_port, end_port, threads):
    global scan_complete, scan_results
    open_ports = []
    port_range_per_thread = (end_port - start_port + 1) // threads
    threads_list = []

    # Split the port range into equal chunks for the threads
    for i in range(threads):
        thread_start_port = start_port + i * port_range_per_thread
        thread_end_port = start_port + (i + 1) * port_range_per_thread - 1 if i < threads - 1 else end_port
        thread = threading.Thread(target=scan_ports, args=(target_ip, thread_start_port, thread_end_port))
        threads_list.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads_list:
        thread.join()

    with scan_lock:
        scan_complete = True  # Mark the scan as complete

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    global scan_results, scan_complete

    try:
        data = request.get_json()  # Get the data sent as JSON
        target_ip = data.get('target_ip')
        start_port = int(data.get('start_port'))
        end_port = int(data.get('end_port'))
        threads = int(data.get('threads'))

        if not target_ip or not start_port or not end_port or not threads:
            return jsonify({"error": "All fields are required."}), 400

        # Reset the results and completion status before starting a new scan
        scan_results = []
        scan_complete = False

        # Start scanning in a separate thread
        thread = threading.Thread(target=start_scanning, args=(target_ip, start_port, end_port, threads))
        thread.start()

        return jsonify({
            "status": "Scanning started",
            "ip": target_ip
        })

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 400

@app.route('/results', methods=['GET'])
def results():
    global scan_results, scan_complete

    # Polling approach: Check if the scan is complete
    if not scan_complete:
        return jsonify({"status": "Scanning", "message": "Scan is still in progress. Please wait."})

    # Retrieve the scan results (open ports) from the global variable
    open_ports = scan_results

    # If no open ports found, return a "No open ports found" message
    if not open_ports:
        return jsonify({"status": "Scan Complete", "message": "No open ports found"})

    return jsonify({"status": "Scan Complete", "open_ports": open_ports})

if __name__ == '__main__':
    app.run(debug=True)
