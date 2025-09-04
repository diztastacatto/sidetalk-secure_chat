import socket
import threading
import json
import os
import time
import base64
import hashlib
import hmac
import getpass
import paramiko
import pyfiglet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend

# Copyright (c) 2023 Golam Mahadi Rafi
# Sidetalk Secure Chat Application
# All rights reserved.
# Unauthorized copying of this file, via any medium is strictly prohibited.

class SidetalkClient:
    def __init__(self, host='127.0.0.1', port=9999, sftp_host='127.0.0.1', sftp_port=2222):
        self.host = host
        self.port = port
        self.sftp_host = sftp_host
        self.sftp_port = sftp_port
        self.app_name = "Sidet@lk"
        self.author = "Golam Mahadi Rafi"
        self.version = "0.0.2"
        self.socket = None
        self.running = False
        self.authenticated = False
        self.username = None
        self.server_signature = None
        self.session_id = None
        self.connection_timeout = 1000  
        self.auth_timeout = 500  
        self.receive_timeout = 500  

    def display_banner(self):
        """Display the application banner with ASCII art using pyfiglet"""
        try:
            # Generate ASCII art banner for the app name
            banner = pyfiglet.figlet_format("Sidet@lk~")
            print(banner)
            # Print the author signature
            print("Made by~  Golam Mahadi Rafi")
            print("-" * 60)
        except Exception as e:
            # Fallback to simple text banner if pyfiglet fails
            print("Sidetalk Secure Chat")
            print("Made by Golam Mahadi Rafi")
            print("-" * 60)
    
    def get_author_signature(self):
        """Return author signature as proof of ownership"""
        return {
            "app_name": self.app_name,
            "author": self.author,
            "signature": hashlib.sha256(f"{self.app_name}{self.author}".encode()).hexdigest(),
            "copyright": f"Copyright (c) 2023 {self.author}"
        }
    
    def connect(self):
        self.display_banner()
        print(f"\nConnecting to {self.app_name} server at {self.host}:{self.port}...")
        
        try:
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.connection_timeout)
            
           
            self.socket.connect((self.host, self.port))
            print(f"Connected to {self.app_name} server!")
            
            
            self.socket.settimeout(self.receive_timeout)
            
            
            print("Waiting for initial data from server...")
            initial_data = self._receive_data()
            if not initial_data:
                print("Failed to receive initial data from server")
                return False
            
            try:
                initial_message = json.loads(initial_data.decode('utf-8'))
                print(f"Received initial data: {initial_message}")
                
                
                self.session_id = initial_message.get('session_id')
                self.server_signature = initial_message.get('app_info')
                
                if self.server_signature:
                    print(f"Server signature: {self.server_signature.get('app_name')} by {self.server_signature.get('author')}")
                
            except json.JSONDecodeError as e:
                print(f"Invalid JSON in initial data: {e}")
                return False
            
            
            self.running = True
            receive_thread = threading.Thread(target=self._receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            
            if not self._authenticate():
                return False
            
            return True
            
        except socket.timeout:
            print(f"Connection timed out after {self.connection_timeout} seconds. The server may not be running.")
            return False
        except ConnectionRefusedError:
            print("Connection refused. The server may not be running.")
            return False
        except Exception as e:
            print(f"Error connecting to server: {e}")
            return False
    
    def disconnect(self):
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        print(f"\nDisconnected from {self.app_name} server.")
    
    def _receive_data(self):
        """Receive raw data from server"""
        try:
            data = self.socket.recv(4096)
            if not data:
                print("No data received - connection closed by server")
                return None
            
            print(f"Received {len(data)} bytes of data")
            return data
        except socket.timeout:
            print("Receive timed out")
            return None
        except Exception as e:
            print(f"Error receiving data: {e}")
            return None
    
    def _send_data(self, data):
        """Send raw data to server"""
        try:
            print(f"Sending {len(data)} bytes of data")
            self.socket.send(data)
            print("Data sent successfully")
            return True
        except Exception as e:
            print(f"Error sending data: {e}")
            return False
    
    def _send_json(self, data):
        """Send JSON data to server"""
        try:
            message_json = json.dumps(data).encode('utf-8')
            return self._send_data(message_json)
        except Exception as e:
            print(f"Error encoding JSON: {e}")
            return False
    
    def _authenticate(self):
        print("\n=== Authentication ===")
        print("Available users: check in users.json")
        print("Default credentials: admin ; password'")
        
        
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        
        
        auth_message = {
            'type': 'auth',
            'username': username,
            'password': password
        }
        
        print("Sending authentication message...")
        if not self._send_json(auth_message):
            print("Failed to send authentication message")
            return False
        
        print("Authentication message sent. Waiting for response...")
        
        
        start_time = time.time()
        while not self.authenticated and self.running:
            if time.time() - start_time > self.auth_timeout:
                print(f"Authentication timed out after {self.auth_timeout} seconds")
                return False
            time.sleep(0.1)
        
        if self.authenticated:
            self.username = username
            print(f"✓ Authentication successful! Welcome, {username}!")
        else:
            print("✗ Authentication failed. Please check your username and password.")
        
        return self.authenticated
    
    def _receive_messages(self):
        print("Message receiver thread started")
        try:
            while self.running:
                print("Waiting for message...")
                data = self._receive_data()
                if not data:
                    print("No message received. Connection may be closed.")
                    self.running = False
                    break
                
                try:
                    message = json.loads(data.decode('utf-8'))
                    print(f"Received message: {message}")
                    
                    msg_type = message.get('type')
                    
                    if msg_type == 'auth_response':
                        
                        success = message.get('success')
                        print(f"Authentication response: success={success}")
                        
                        if success:
                            self.authenticated = True
                            
                            if 'app_info' in message:
                                self.server_signature = message['app_info']
                        else:
                            print(f"Authentication failed: {message.get('message')}")
                    
                    elif msg_type == 'message':
                        
                        sender = message.get('sender')
                        message_text = message.get('message')
                        timestamp = message.get('timestamp')
                        
                        
                        if 'app_info' in message:
                            app_info = message['app_info']
                            if app_info.get('app_name') != self.app_name:
                                print("Warning: Message from unrecognized application")
                        
                        time_str = time.strftime('%H:%M:%S', time.localtime(timestamp))
                        
                        
                        if sender == self.username:
                            print(f"\n[{time_str}] You: {message_text}")
                        else:
                            print(f"\n[{time_str}] {sender}: {message_text}")
                        
                        
                        if self.authenticated:
                            print(f"{self.username}> ", end="", flush=True)
                    
                    elif msg_type == 'file_info':
                        
                        filename = message.get('filename')
                        size = message.get('size')
                        client = message.get('client')
                        
                        
                        if 'app_info' in message:
                            app_info = message['app_info']
                            if app_info.get('app_name') != self.app_name:
                                print("Warning: File info from unrecognized application")
                        
                        print(f"\n📁 File transfer: {filename} ({size} bytes) from {client}")
                        print(f"{self.username}> ", end="", flush=True)
                    
                except json.JSONDecodeError as e:
                    print(f"Invalid JSON received: {e}")
                
        except Exception as e:
            print(f"Error in message receiver: {e}")
            self.running = False
        finally:
            print("Message receiver thread ended")
    
    def send_chat_message(self, message_text):
        if not self.authenticated:
            print("Not authenticated")
            return False
        
        message = {
            'type': 'message',
            'message': message_text,
            'app_info': self.get_author_signature()
        }
        
        return self._send_json(message)
    
    def send_file(self, filepath):
        if not self.authenticated:
            print("Not authenticated")
            return False
        
        if not os.path.exists(filepath):
            print(f"File not found: {filepath}")
            return False
        
        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)
        
        
        file_request = {
            'type': 'file_request',
            'filename': filename,
            'size': file_size,
            'app_info': self.get_author_signature()
        }
        
        if not self._send_json(file_request):
            return False
        
        
        try:
            
            transport = paramiko.Transport((self.sftp_host, self.sftp_port))
            transport.connect(username='sftp', password='sftppassword')
            
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            
            print(f"Uploading {filename}...")
            sftp.put(filepath, f'upload/{filename}')
            print(f"✓ File {filename} uploaded successfully to {self.app_name} server")
            
            # Close SFTP connection
            sftp.close()
            transport.close()
            
            return True
            
        except Exception as e:
            print(f"Error uploading file: {e}")
            return False
    
    def download_file(self, filename, local_path='.'):
        if not self.authenticated:
            print("Not authenticated")
            return False
        
        
        try:
            
            transport = paramiko.Transport((self.sftp_host, self.sftp_port))
            transport.connect(username='sftp', password='sftppassword')
            
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            
            print(f"Downloading {filename} from {self.app_name} server...")
            sftp.get(f'download/{filename}', os.path.join(local_path, filename))
            print(f"✓ File {filename} downloaded successfully")
            
            
            sftp.close()
            transport.close()
            
            return True
            
        except Exception as e:
            print(f"Error downloading file: {e}")
            return False
    
    def run(self):
        if not self.connect():
            return
        
        try:
            print("\n=== Sidetalk Secure Chat ===")
            print("Commands:")
            print("  /sendfile <path>  - Upload a file")
            print("  /getfile <name>   - Download a file")
            print("  exit             - Exit the application")
            print("=====================================")
            
            while self.running and self.authenticated:
                try:
                    message_text = input(f"{self.username}> ")
                    if message_text.lower() in ['exit', 'quit']:
                        break
                    
                    if message_text.startswith('/sendfile '):
                        filepath = message_text[10:].strip()
                        self.send_file(filepath)
                    elif message_text.startswith('/getfile '):
                        filename = message_text[9:].strip()
                        self.download_file(filename)
                    else:
                        self.send_chat_message(message_text)
                        
                except KeyboardInterrupt:
                    print("\nExiting...")
                    break
                except EOFError:
                    print("\nExiting...")
                    break
                    
        finally:
            self.disconnect()

if __name__ == "__main__":
    client = SidetalkClient()
    client.run()
    
