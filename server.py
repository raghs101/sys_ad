import socket
import threading
import os
import re
import zipfile
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import mysql.connector

# User files database (username: {filename: filepath})
user_files = {
    'user1': {'file1.txt': 'user1/file1.txt'},
    'user2': {'file2.txt': 'user2/file2.txt'}
}

# Database connection
conn = mysql.connector.connect(
    host='localhost',
    user='root',
    password='delta@sql',
    database='server'
)

def handle_client(client_socket):
    authenticated = False

    while not authenticated:
        request = client_socket.recv(1024).decode('utf-8')
        print(request)
        if request == 'authenticate':
            authenticated = authenticate(client_socket)
        else:
            client_socket.send('Please authenticate first.'.encode('utf-8'))

    if not authenticated:
        client_socket.close()
        return

    while True:
        request = client_socket.recv(1024).decode('utf-8')
        if request == 'upload':
            client_socket.send('Please specify the folder/file path.'.encode('utf-8'))
            path = client_socket.recv(1024).decode('utf-8')
            if os.path.isdir(path):
                upload_folder(client_socket, path)
            else:
                upload_file(client_socket, path)
        elif request == 'search':
            client_socket.send('Please specify the regex pattern.'.encode('utf-8'))
            regex_pattern = client_socket.recv(1024).decode('utf-8')
            matching_files = search_files(regex_pattern)
            file_list = '\n'.join(matching_files)
            client_socket.send(file_list.encode('utf-8'))
        elif request == 'remove':
            client_socket.send('Please specify the file name.'.encode('utf-8'))
            file_name = client_socket.recv(1024).decode('utf-8')
            response = remove_file(file_name)
            client_socket.send(response.encode('utf-8'))
        elif request == 'download':
            client_socket.send('Please specify the file name.'.encode('utf-8'))
            file_name = client_socket.recv(1024).decode('utf-8')
            if file_name in user_files[username]:
                file_path = user_files[username][file_name]
                encrypted_data = encrypt_file(file_path)
                client_socket.sendall(encrypted_data)
            else:
                client_socket.send('File not found or unauthorized access.'.encode('utf-8'))
        elif request == 'exit':
            break

    client_socket.close()

def authenticate(client_socket):
    client_socket.send("Please enterusername and password".encode())
    username = client_socket.recv(1024).decode('utf-8')
    password = client_socket.recv(1024).decode('utf-8')

    cursor = conn.cursor()
    query = "SELECT * FROM client WHERE username = %s AND password = %s"
    cursor.execute(query, (username, password))
    result = cursor.fetchone()

    if result:
        client_socket.send('Authentication successful.'.encode('utf-8'))
        return True
    else:
        client_socket.send('Authentication failed.'.encode('utf-8'))
        return False

def upload_folder(client_socket, folder_path):
    folder_name = os.path.basename(folder_path)
    zip_name = folder_name + '.zip'
    zip_path = os.path.join(folder_path, zip_name)

    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zip_file:
        for root, _, files in os.walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                zip_file.write(file_path, os.path.relpath(file_path, folder_path))

    encrypted_data = encrypt_file(zip_path)
    client_socket.sendall(encrypted_data)


    response = client_socket.recv(1024).decode('utf-8')
    print(response)

    os.remove(zip_path)

def upload_file(client_socket, file_path):
    file_name = os.path.basename(file_path)

    encrypted_data = encrypt_file(file_path)
    client_socket.sendall(encrypted_data)

    response = client_socket.recv(1024).decode('utf-8')
    print(response)

def search_files(regex_pattern):
    matching_files = []
    for filename, _ in user_files[username].items():
        if re.search(regex_pattern, filename):
            matching_files.append(filename)
    return matching_files

def remove_file(file_name):
    if file_name in user_files[username]:
        file_path = user_files[username].pop(file_name)
        os.remove(file_path)
        return 'File removed successfully.'
    else:
        return 'File not found or unauthorized access.'

def encrypt_file(file_path):
    key = b'SuperSecretKey123'
    cipher = AES.new(key, AES.MODE_CBC)

    with open(file_path, 'rb') as file:
        data = file.read()
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)

    return cipher.iv + encrypted_data

def decrypt_file(file_path, encrypted_data):
    key = b'SuperSecretKey123'
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_data = cipher.decrypt(encrypted_data[AES.block_size:])
    unpadded_data = unpad(decrypted_data, AES.block_size)

    with open(file_path, 'wb') as file:
        file.write(unpadded_data)

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 9999))
    server_socket.listen(5)
    print('Server started.')

    while True:
        client_socket, addr = server_socket.accept()
        print(f'New connection from {addr[0]}:{addr[1]}')
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()

start_server()
