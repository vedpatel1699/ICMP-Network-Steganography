# This code include encryption + Latency Label + Copy Button

import tkinter as tk
import socket, time
from PIL import Image, ImageTk, ImageFilter
from tkinter import ttk, messagebox
from scapy.all import *
import threading
import time
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Global variable to track the sequence number
sequence_number = 1
progress_counter = 0


# Function to generate AES key from sender's IP and a pre-shared salt
def generate_aes_key_from_ip_with_salt(ip_address, secret_salt):
    combined_input = f"{ip_address}{secret_salt}".encode()
    hash_object = hashlib.sha256(combined_input)
    aes_key = hash_object.digest()[:16]

    log_box.insert(tk.END, f"Debug Logs of Sender Script\n")
    log_box.insert(tk.END, f"Sender IP: {ip_address}\n")
    log_box.insert(tk.END, f"Secret Salt: {secret_salt}\n")
    log_box.insert(tk.END, f"Combined Input for Key: {combined_input.decode('utf-8')}\n")
    log_box.see(tk.END)
    log_box.insert(tk.END, f"Hash Output: {hash_object.hexdigest()}\n")
    log_box.see(tk.END)
    log_box.insert(tk.END, f"AES Key: {aes_key.hex()}\n")
    log_box.see(tk.END)
    return aes_key

# Function to get the actual IP address of the sender
def get_sender_ip(target_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 1))  # Connect to target IP to determine the sender's outbound IP
        sender_ip = s.getsockname()[0]
    except Exception:
        sender_ip = "127.0.0.1"  # Default to localhost in case of error
    finally:
        s.close()
    return sender_ip

# Function to encrypt the message
def encrypt_message(aes_key, message):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    return encrypted_message.decode('latin1')  # Convert encrypted bytes to characters

# Function to send ICMP message
def send_icmp_message(target_ip, message, sender_id):
    global sequence_number  # Use the global sequence number
    global progress_counter

    # Hash the sender ID to MD5
    sender_id_hash = hashlib.md5(sender_id.encode()).hexdigest()

    # Ensure sender ID is exactly 8 characters before hashing
    if len(sender_id) != 8:
        log_box.insert(tk.END, "Error: Sender ID must be exactly 8 characters.\n")
        log_box.see(tk.END)
        return

    # Generate AES key using sender IP and salt
    secret_salt = "#{[F,1A7y)F:0k!pS6"  # Pre-shared salt
    sender_ip = get_sender_ip(target_ip)
    aes_key = generate_aes_key_from_ip_with_salt(sender_ip, secret_salt)
    log_box.insert(tk.END, f"\n\nAES Key: {aes_key.hex()}\n")
    log_box.see(tk.END)

    # Encrypt the message and convert it to characters
    encrypted_message = encrypt_message(aes_key, message)
    full_message = encrypted_message + '\n'  # Add termination character
    total_chars = len(sender_id_hash) + len(full_message)

    # Set the progress bar maximum value to total characters
    progress_bar['maximum'] = total_chars
    progress_bar['value'] = 0  # Reset the progress bar
    progress_label.config(text="Progress: 0%")  # Reset the label

    # Send the total number of characters
    packet = IP(dst=target_ip) / ICMP(type=8, code=total_chars, id=sequence_number)
    log_box.insert(tk.END, f"Sending total character count: {total_chars}\n")
    log_box.see(tk.END)
    send(packet, verbose=False)
    sequence_number += 1

    # Send the hashed sender ID (32 characters)
    for char in sender_id_hash:
        timestamp = str(time.time())  # Current time in seconds (as a float)
        payload = f"{char}|{timestamp}"  # Add timestamp to the payload
        packet = IP(dst=target_ip) / ICMP(type=8, code=ord(char), id=sequence_number) / payload
        send(packet, verbose=False)
        sequence_number += 1

        # Update progress bar for each character
        progress_counter += 1
        progress_bar['value'] = progress_counter
        progress_label.config(text=f"Progress: {int(progress_counter / total_chars * 100)}%")
        log_box.insert(tk.END, f"Sent character (Sender ID Hash): {char}\n")
        log_box.see(tk.END)

        # Add a small delay to avoid flooding the network
        time.sleep(1)

    # Send the encrypted message character by character
    for i, char in enumerate(full_message):
        timestamp = str(time.time())  # Current time in seconds (as a float)
        payload = f"{char}|{timestamp}"  # Add timestamp to the payload
        packet = IP(dst=target_ip) / ICMP(type=8, code=ord(char), id=sequence_number) / payload
        send(packet, verbose=False)

        # Update progress bar
        progress_counter += 1
        progress_bar['value'] = progress_counter
        progress_label.config(text=f"Progress: {int(progress_counter / total_chars * 100)}%")
        log_box.insert(tk.END, f"Sent character (Encrypted Message): {char}\n")
        log_box.see(tk.END)

        # Add a small delay to avoid flooding the network
        time.sleep(1)

        # Increment the sequence number for the next packet
        sequence_number += 1

    log_box.insert(tk.END, f"\nEncrypted Message Sent: {encrypted_message}\n")
    log_box.see(tk.END)

    log_box.insert(tk.END, "Message sent. Waiting for acknowledgment...\n")
    log_box.see(tk.END)

    # Start a listener for the acknowledgment from the receiver
    listen_for_acknowledgment(target_ip)

# Function to listen for ICMP Echo Reply (Acknowledgment)
def listen_for_acknowledgment(target_ip):
    global progress_counter
    def acknowledgment_callback(packet):
        global progress_counter
        if packet.haslayer(ICMP) and packet[ICMP].type == 0: # ICMP Echo Reply
            log_box.insert(tk.END, "Acknowledgment received from receiver.\n")
            log_box.see(tk.END)
            
            # Reset progress bar
            progress_counter=0
            progress_bar['value'] = 0
            progress_label.config(text="Progress: 0%")

    # Sniff for acknowledgment (1 packet only)
    sniff(filter=f"icmp and src {target_ip}", prn=acknowledgment_callback, count=1)

# Function to handle the Send button click
def handle_send():
    target_ip = target_ip_entry.get().strip()
    message = message_entry.get("1.0", tk.END).strip()
    sender_id = sender_id_entry.get().strip()

    if not target_ip or not message or not sender_id:
        messagebox.showerror("Error", "Please fill in all fields.")
        return

    log_box.insert(tk.END, f"Starting to send message to {target_ip}\n")
    log_box.see(tk.END)

    # Start sending the message in a separate thread
    send_thread = threading.Thread(target=send_icmp_message, args=(target_ip, message, sender_id))
    send_thread.start()

# Function to copy all the log box content to clipboard
def copy_to_clipboard():
    log_content = log_box.get("1.0", tk.END)  # Get all content from the log box
    app.clipboard_clear()  # Clear current clipboard
    app.clipboard_append(log_content)  # Append the log content to clipboard
    app.update()  # Update the clipboard content

# GUI Application Setup
app = tk.Tk()
app.title("ICMP Steganography Message Sender")
app.geometry("550x650")

# Background image setup
background_image = Image.open("background.jpg")  # Replace with your image file path
background_blur = background_image.filter(ImageFilter.GaussianBlur(radius=10))
background_photo = ImageTk.PhotoImage(background_blur)

background_label = tk.Label(app, image=background_photo)
background_label.place(x=0, y=0, relwidth=1, relheight=1)

# Input fields and layout
frame = tk.Frame(app, bg="#3a3a3a")
frame.pack(fill="both", expand=True, padx=20, pady=20)

header_label = tk.Label(frame, text="GhostPacket Gr-3 Sender", font=("Helvetica", 16, "bold"), fg="#4CAF50", bg=frame['bg'])
header_label.pack(pady=10)

target_ip_label = tk.Label(frame, text="Target IP Address:", font=("Helvetica", 12), fg="white", bg=frame['bg'])
target_ip_label.pack(pady=(10, 0))
target_ip_entry = tk.Entry(frame, width=40, font=("Helvetica", 12))
target_ip_entry.pack()

message_label = tk.Label(frame, text="Message to Send:", font=("Helvetica", 12), fg="white", bg=frame['bg'])
message_label.pack(pady=(10, 0))
message_entry = tk.Text(frame, width=50, height=3, font=("Helvetica", 12))
message_entry.pack()

sender_id_label = tk.Label(frame, text="8-Character Sender ID:", font=("Helvetica", 12), fg="white", bg=frame['bg'])
sender_id_label.pack(pady=(10, 0))
sender_id_entry = tk.Entry(frame, width=40, font=("Helvetica", 12))
sender_id_entry.pack()

send_button = tk.Button(frame, text="Send", font=("Helvetica", 12, "bold"), bg="#4CAF50", fg="white", command=handle_send)
send_button.pack(pady=(10, 0))

progress_bar = ttk.Progressbar(frame, length=300, mode='determinate')
progress_bar.pack(pady=(20, 0))
progress_label = tk.Label(frame, text="Progress: 0%", font=("Helvetica", 12), fg="white", bg=frame['bg'])
progress_label.pack()

log_label = tk.Label(frame, text="Log Box:", font=("Helvetica", 12), fg="white", bg=frame['bg'])
log_label.pack(pady=(10, 0))
log_box = tk.Text(frame, width=60, height=10, font=("Helvetica", 10), bg="#1e1e1e", fg="white", relief="solid")
log_box.pack(pady=5)

# Copy button
copy_button = tk.Button(frame, text="Copy Logs", font=("Helvetica", 10), fg="black", bg="#d8dce3", command=copy_to_clipboard)
copy_button.pack(side="right", padx=43, pady=5)  # Place button on the right, with padding

# Start the GUI application
app.mainloop()