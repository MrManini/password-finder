import pandas as pd
import threading
from Crypto.Hash import SHA3_512
import time

password_df = pd.read_csv('password_database_ED2.csv')
with open('rockyou.txt', 'r', encoding='iso-8859-1') as file:
    lines = file.readlines()
possible_passwords = [line.rstrip('\n') for line in lines]

row_df = password_df[password_df['username'] == 'kjtorregrosa']
username, salt, password = row_df.values.tolist()[0]

# Shared flag to indicate if password is found
password_found = False
lock = threading.Lock()

# Function to try a single password with threading
def try_password_thread(possible_passwords, salt, password):
    global password_found
    for possible_password in possible_passwords:
        if password_found:
            break
        for pepper in range(256):
            H = SHA3_512.new()
            H.update(bytes(possible_password, 'iso-8859-1'))
            H.update(pepper.to_bytes(1, byteorder='big'))
            H.update(bytes.fromhex(salt))

            if H.hexdigest() == password:
                print(f"Password found: {possible_password}")
                with lock:
                    password_found = True
                break

# Function to divide work among threads
def find_password_threaded(possible_passwords, salt, password, num_threads):
    threads = []
    chunk_size = len(possible_passwords) // num_threads
    for i in range(num_threads):
        start_index = i * chunk_size
        end_index = (i + 1) * chunk_size if i < num_threads - 1 else len(possible_passwords)
        thread = threading.Thread(target=try_password_thread, args=(possible_passwords[start_index:end_index], salt, password))
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

# Call the function with the list of possible passwords and number of threads
num_threads = 4 # Adjust this number based on your system's capabilities
start = time.time()
find_password_threaded(possible_passwords, salt, password, num_threads)
end = time.time()

if password_found:
    print(f"Password found in {end - start} seconds.")
else:
    print("Password not found.")
