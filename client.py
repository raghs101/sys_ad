import socket
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def authenticate():
    client_socket.send('authenticate'.encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    print(response)

    username = input("Username: ")
    password = input("Password: ")

    client_socket.send(username.encode('utf-8'))
    client_socket.send(password.encode('utf-8'))

    authentication_result = client_socket.recv(1024).decode('utf-8')
    print(authentication_result)

    return authentication_result == 'Authentication successful.'

def upload_folder(folder_path):
    if not authenticate():
        return

    client_socket.send('upload'.encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    print(response)

    client_socket.send(folder_path.encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    print(response)

    file_list = []
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            file_list.append(file_path)

    for file_path in file_list:
        file_name = os.path.basename(file_path)
        encrypted_data = encrypt_file(file_path)
        client_socket.sendall(encrypted_data)
        response = client_socket.recv(1024).decode('utf-8')
        print(response)

def search_files(regex_pattern):
    if not authenticate():
        return

    client_socket.send('search'.encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    print(response)

    client_socket.send(regex_pattern.encode('utf-8'))
    file_list = client_socket.recv(1024).decode('utf-8')
    print(file_list)

def remove_file(file_name):
    if not authenticate():
        return

    client_socket.send('remove'.encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    print(response)

    client_socket.send(file_name.encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    print(response)

def encrypt_file(file_path):
    key = b'SuperSecretKey123'
    cipher = AES.new(key, AES.MODE_CBC)

    with open(file_path, 'rb') as f:
        data = f.read()
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)

    return cipher.iv + encrypted_data

def decrypt_file(file_path, encrypted_data):
    key = b'SuperSecretKey123'
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_data = cipher.decrypt(encrypted_data[AES.block_size:])
    unpadded_data = unpad(decrypted_data, AES.block_size)

    with open(file_path, 'wb') as f:
        f.write(unpadded_data)

def upload_file(file_path):
    if not authenticate():
        return

    client_socket.send('upload'.encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    print(response)

    client_socket.send(file_path.encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    print(response)

    encrypted_data = encrypt_file(file_path)
    client_socket.sendall(encrypted_data)
    response = client_socket.recv(1024).decode('utf-8')
    print(response)

def download_file(file_name):
    if not authenticate():
        return

    client_socket.send('download'.encode('utf-8'))
    response = client_socket.recv(1024).decode('utf-8')
    print(response)

    client_socket.send(file_name.encode('utf-8'))
    encrypted_data = b''
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        encrypted_data += data

    decrypt_file(file_name, encrypted_data)
    print(f'{file_name} downloaded and stored as {file_name}')

# Create a socket connection to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 9999))
print("Login:")
authenticate()



# Specify the folder path to upload
upload_folder('folder_path')

# Search for files using regex pattern
search_files('.*\.txt')

# Remove a file
remove_file('file.txt')

# Upload a single file
upload_file('file.txt')

# Download a file
download_file('file.txt')

# Close the socket connection
client_socket.close()
