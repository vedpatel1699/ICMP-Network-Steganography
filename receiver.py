# This code include encryption + Latency Label + Copy Button

import tkinter as tk
import os
from PIL import Image, ImageTk, ImageFilter
from tkinter import ttk
from scapy.all import *
import time
import threading
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Global variables
received_message = []
sender_ip = None
receiving_started = False
total_chars = 0
status = "Listening"
sender_keys = {}
processed_seq_nums = set()
flash_count = 0
flashing = False
sender_id_name = None  # To store the sender's name after hash validation
empty_packet_counter=0
last_gui_update_time = 0  # Track the last time the GUI was updated

# Load sender keys from JSON file
def load_sender_keys():
    global sender_keys
    #print(f"Current Working Directory: {os.getcwd()}")
    try:
        with open('sender_keys.json', 'r') as f:
            sender_keys = json.load(f)
    except FileNotFoundError:
        log_box.insert(tk.END, "Error: sender_keys.json file not found.\n")
        log_box.see(tk.END)
        sender_keys = {}

# Function to generate AES key from sender's IP and a pre-shared salt
def generate_aes_key_from_ip_with_salt(ip_address, secret_salt):
    combined_input = f"{ip_address}{secret_salt}".encode()
    hash_object = hashlib.sha256(combined_input)
    aes_key = hash_object.digest()[:16]
    
    log_box.insert(tk.END, f"Debug Logs of Receiver Script\n")
    log_box.insert(tk.END, f"Sender IP: {ip_address}\n")
    log_box.insert(tk.END, f"Secret Salt: {secret_salt}\n")
    log_box.insert(tk.END, f"Combined Input for Key: {combined_input.decode('utf-8')}\n")
    log_box.see(tk.END)
    log_box.insert(tk.END, f"Hash Output: {hash_object.hexdigest()}\n")
    log_box.see(tk.END)
    log_box.insert(tk.END, f"AES Key: {aes_key.hex()}\n")
    log_box.see(tk.END)
    return aes_key

# Function to decrypt the message
def decrypt_message(aes_key, encrypted_message):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size).decode()
    return decrypted_message

# Function to update the latency label
def update_latency_gui(latency):
    global last_gui_update_time
    current_time = time.time()
    if current_time - last_gui_update_time > 0.1:  # Update GUI every 100 ms
        latency_label.config(text=f"Latency: {latency:.2f} ms")
        last_gui_update_time = current_time

# Extract hidden message from ICMP packets
def icmp_packet_callback(packet):
    global received_message, sender_ip, receiving_started, total_chars, status, flashing, processed_seq_nums, sender_id_name, empty_packet_counter

    if packet.haslayer(ICMP):
        icmp_layer = packet.getlayer(ICMP)
    
    if icmp_layer.code == 10:
        empty_packet_counter += 1

    if packet.haslayer(IP) and packet.haslayer(ICMP):
        ip_layer = packet[IP]
        icmp_layer = packet[ICMP]

        if sender_ip is None:
            sender_ip = ip_layer.src

        seq_num = icmp_layer.id
        if seq_num in processed_seq_nums:
            return

        processed_seq_nums.add(seq_num)

        # First packet: Total number of characters
        if not receiving_started and icmp_layer.type == 8:
            total_chars = icmp_layer.code
            log_box.insert(tk.END, f"Total number of characters to be received: {total_chars}\n")
            log_box.see(tk.END)
            status = "Receiving"
            update_status()
            
            # Reset the empty packet counter for the new message cycle
            empty_packet_counter = 0
            #log_box.insert(tk.END, "Empty packet counter reset for the new message cycle.\n")
            log_box.see(tk.END)

            receiving_started = True
            return

        if empty_packet_counter <=1 :
            
            payload = bytes(packet[Raw].load).decode('latin1')  # Decode the payload
            char, sent_timestamp = payload.split('|')  # Split into character and timestamp

            # Calculate latency
            sent_time = float(sent_timestamp)  # Convert timestamp to float
            received_time = time.time()
            latency = (received_time - sent_time) * 100  # Converting to appropriate format

            # Update the latency label
            #atency_label.config(text=f"Latency: {latency:.2f} ms")
            update_latency_gui(latency)
            
            # Process characters
            hidden_char = chr(icmp_layer.code)
            received_message.append(hidden_char)
            progress_bar['value'] = len(received_message) / total_chars * 100
            progress_label.config(text=f"Progress: {int(len(received_message) / total_chars * 100)}%")
            log_box.insert(tk.END, f"Received character: {hidden_char}\n")
            log_box.see(tk.END)

            # Process sender ID hash (32 characters)
            if len(received_message) == 32:
                sender_hash_received = ''.join(received_message[:32])
                log_box.insert(tk.END, f"Received sender hash: {sender_hash_received}\n")
                log_box.see(tk.END)

                # Validate sender hash
                if sender_hash_received in sender_keys:
                    sender_id_name = sender_keys[sender_hash_received]
                    log_box.insert(tk.END, f"Valid sender hash matched. Sender: {sender_id_name}\n")
                    log_box.see(tk.END)
                else:
                    log_box.insert(tk.END, "Invalid sender hash. Dropping packet.\n")
                    reset_for_next_cycle()
                    return

            # Process actual encrypted message
            if len(received_message) > 32:
                # Check for termination character
                if hidden_char == '\n':  # Termination character is '\n'
                    log_box.insert(tk.END, "Termination character received. Assembling message...\n")
                    log_box.see(tk.END)
                    assemble_message()
                    send_acknowledgment(sender_ip)

                    # Reset progress bar
                    progress_bar['value'] = 0
                    progress_label.config(text="Progress: 0%")
                    reset_for_next_cycle()


# Assemble the full hidden message
def assemble_message():
    global received_message, total_chars

    try:
        # Combine characters to form the encrypted message
        encrypted_message_chars = received_message[32:-1]  # Exclude sender hash and termination character
        encrypted_message = ''.join(encrypted_message_chars).encode('latin1')  # Convert to bytes for decryption

        # Pre-shared salt for AES key generation
        secret_salt = "#{[F,1A7y)F:0k!pS6"  # Pre-shared salt

        # Generate AES key using sender IP and salt
        aes_key = generate_aes_key_from_ip_with_salt(sender_ip, secret_salt)

        # Log the encrypted message before decryption
        log_box.insert(tk.END, f"Encrypted Message Reassembled: {encrypted_message}\n")
        log_box.see(tk.END)

        # Decrypt the message
        decrypted_message = decrypt_message(aes_key, encrypted_message)

        # Log and display the decrypted message
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        log_box.insert(tk.END, f"\nFull decrypted message: {decrypted_message}\n")
        log_box.insert(tk.END, f"Sender: {sender_id_name}\n")
        log_box.insert(tk.END, f"Received From: {sender_ip}\n")
        log_box.insert(tk.END, f"Time of Reception: {current_time}\n\n")
        log_box.see(tk.END)

    except Exception as e:
        # Log error and reset for next cycle
        log_box.insert(tk.END, f"Error while assembling message: {str(e)}\n")
        log_box.see(tk.END)
        reset_for_next_cycle()


# Reset variables and status for the next message cycle
def reset_for_next_cycle():
    global received_message, sender_ip, receiving_started, total_chars, status, sender_id_name, empty_packet_counter

    received_message.clear()
    sender_ip = None
    receiving_started = False
    #total_chars = 0
    sender_id_name = None
    status = "Listening"
    update_status()
    log_box.insert(tk.END, "Ready to receive the next message...\n")
    log_box.see(tk.END)
    #time.sleep(8)

# Send acknowledgment back to the sender
def send_acknowledgment(dst_ip):
    global status
    status = "Acknowledging"
    update_status()
    log_box.insert(tk.END, "Sending acknowledgment to sender...\n")
    time.sleep(4)
    log_box.see(tk.END)
    original_verbosity = conf.verb
    conf.verb = 0
    ack_packet = IP(dst=dst_ip) / ICMP(type=0)
    send(ack_packet)
    conf.verb = original_verbosity
    log_box.insert(tk.END, "Acknowledgment sent.\n\n")
    log_box.see(tk.END)

# Update the status label with color
def update_status():
    if status == "Listening":
        status_label_status.config(text=status, fg="#E1E386")
    elif status == "Receiving":
        status_label_status.config(text=status, fg="#5da854")
    elif status == "Assembling":
        status_label_status.config(text=status, fg="#e08989")
    elif status == "Acknowledging":
        status_label_status.config(text=status, fg="#808080")

# Sniff ICMP packets in a separate thread
def start_sniffing():
    sniff(filter="icmp", prn=icmp_packet_callback)
    
# Function to copy all the log box content to clipboard
def copy_to_clipboard():
    log_content = log_box.get("1.0", tk.END)  # Get all content from the log box
    app.clipboard_clear()  # Clear current clipboard
    app.clipboard_append(log_content)  # Append the log content to clipboard
    app.update()  # Update the clipboard content

# GUI Setup
app = tk.Tk()
app.title("ICMP Steganography Message Receiver")
app.geometry("550x650")

# Background image setup
background_image = Image.open("background.jpg")  # Replace with your image file path
background_blur = background_image.filter(ImageFilter.GaussianBlur(radius=10))
background_photo = ImageTk.PhotoImage(background_blur)

background_label = tk.Label(app, image=background_photo)
background_label.place(x=0, y=0, relwidth=1, relheight=1)

# GUI Design
frame = tk.Frame(app, bg="#3a3a3a")
frame.pack(fill="both", expand=True, padx=20, pady=20)

header_label = tk.Label(frame, text="GhostPacket Gr-3 Receiver", font=("Helvetica", 16, "bold"), fg="#4CAF50", bg=frame['bg'])
header_label.pack(pady=10)

progress_bar = ttk.Progressbar(frame, length=300, mode='determinate')
progress_bar.pack(pady=(5, 0))
progress_label = tk.Label(frame, text="Progress: 0%", font=("Helvetica", 12), fg="white", bg=frame['bg'])
progress_label.pack()

status_frame = tk.Frame(frame, bg=frame['bg'])
status_frame.pack(pady=(18, 10))

status_label = tk.Label(status_frame, text="Status: ", font=("Helvetica", 12), fg="white", bg=frame['bg'])
status_label.pack(side="left")
status_label_status = tk.Label(status_frame, text=status, font=("Helvetica", 12), fg="#E1E386", bg=frame['bg'])
status_label_status.pack(side="left")

# Latency label
latency_label = tk.Label(frame, text="Latency: 0 ms", font=("Helvetica", 12), fg="white", bg=frame['bg'])
latency_label.pack(pady=(10, 0))

log_label = tk.Label(frame, text="Log Box:", font=("Helvetica", 12), fg="white", bg=frame['bg'])
log_label.pack(pady=(10, 0))
log_box = tk.Text(frame, width=60, height=10, font=("Helvetica", 10), bg="#1e1e1e", fg="white", relief="solid")
log_box.pack(pady=5)

# Copy button
copy_button = tk.Button(frame, text="Copy Logs", font=("Helvetica", 10), fg="black", bg="#d8dce3", command=copy_to_clipboard)
#copy_button.pack(side="right", padx=43, pady=5)  # Place button on the right, with padding
copy_button.pack(side="right", anchor="ne", padx=43, pady=(10, 0))



# Load sender keys
load_sender_keys()

# Start sniffing in a separate thread
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.daemon = True
sniff_thread.start()

# Start the GUI
app.mainloop()