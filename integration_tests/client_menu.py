import time
from random import randint

from client.main import Client
from utils.connection_env import SERVER_PORT

client = Client("localhost", SERVER_PORT, id=56)
client.connect()

while True:
    command = input("Enter a command: ")
    if command == "quit":
        print("Quitting...")
        break
    elif command == "help":
        print(
            "Available commands:\n1.quit\n2.help\n3.register\n4.login\n5.show online users\n6.send message\n7.show recieved message")
    elif command == "register":
        username = input("Enter username: ")
        password = input("Enter password: ")
        response = client.send_register_request(username, password)
        print(response)
    elif command == "login":
        username = input("Enter username: ")
        password = input("Enter password: ")
        response = client.send_login_request(username, password)
        if response:
            print("Successful")
        else:
            print("Failed")
    elif command == "show online users":
        if not client.username:
            print("You need to login first.")
            continue
        response = client.send_online_users_list_request()
        if response:
            print(response)
        else:
            print("Failed")
    elif command == "send message":
        reciever = input("Enter reciever: ")
        message = input("Enter message: ")
        if not client.session_keys[reciever]:
            client.send_handshake_request(reciever)
            time.sleep(1)
        before = len(client.messages[reciever])
        client.send_message(reciever, 'hi')
        time.sleep(1)
        if before < len(client.messages[reciever]):
            print('Message has been sent')
        else:
            print('Failed to send message')
    elif command == "show messages":
        reciever = input("Enter reciever: ")
        print(client.show_messages(reciever))
    elif command == "check session security":
        symbol = input("Choose one of these symbols: $,#,@ ")
        # check_security
    else:
        print("Unknown command. Type 'help' for a list of available commands.")
