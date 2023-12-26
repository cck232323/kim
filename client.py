import socket
import sys
import time
import threading

if len(sys.argv) != 4:
    print("\n===== Error usage, python3 Client.py SERVER_IP TCP_PORT UDP_PORT ======\n")
    exit(0)

server_ip, tcp_port, udp_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
server_address = (server_ip, tcp_port)

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(server_address)
logout_event = threading.Event()
print_event = threading.Event()

COMMAND_PROMPT = "Enter one of the following commands (/msgto, /activeuser, /creategroup, /joingroup, /groupmsg, /p2pvideo, /logout): "

while True:
    print("> Please login")
    username = input("Username: ")
    password = input("Password: ")

    credentials = {"username": username, "password": password}
    client_socket.sendall(str(credentials).encode())

    data = client_socket.recv(1024)
    received_message = data.decode()

    while True:
        if received_message == "Authentication successful":
            print("Welcome to TESSENGER!")
            client_socket.sendall(str(udp_port).encode())
            break
        elif received_message == "Invalid Password. Please try again.":
            print(received_message)
            password = input("Password: ")
            credentials = {"username": username, "password": password}
            client_socket.sendall(str(credentials).encode())
        elif received_message == "Invalid Username. Please try again.":
            print(received_message)
            username = input("Username: ")
            password = input("Password: ")
            credentials = {"username": username, "password": password}
            client_socket.sendall(str(credentials).encode())
        elif received_message.startswith("Your account is blocked"):
            print(received_message)
            time.sleep(10)
            username = input("Username: ")
            password = input("Password: ")
            credentials = {"username": username, "password": password}
            client_socket.sendall(str(credentials).encode())
        elif received_message.startswith("no other active user"):
            print("[recv] No other active users.")
        elif ":" in received_message:  # Check if the message has IP and port, to recognize active user responses
            print("[recv] Active users:\n", received_message)
        else:
            print("[recv] Unexpected message from server:", received_message)
            client_socket.close()
            exit(0)
        data = client_socket.recv(1024)
        received_message = data.decode()

    if received_message == "Authentication successful":
        break

running = True

def receive_messages():
    global running
    while running:
        try:
            data = client_socket.recv(1024)
            if not data:
                break
            received_message = data.decode()
            if received_message == "":
                print("[recv] Message from server is empty!")
            elif received_message.startswith("Error"):
                print("[recv]", received_message)
            elif received_message == "You have successfully logged out.":
                print(received_message)  # 显示登出信息
                logout_event.set()
                client_socket.close()  # 关闭客户端套接字
                running = False
                break  # 退出循环，终止程序
            else:
                print(f"\n{received_message}")
                print(COMMAND_PROMPT)
        except Exception as e:
            print("Receive message error:", e)
            break

# Start the receive_messages function as a new thread
threading.Thread(target=receive_messages).start()

while True:
    # print_event.wait()  # 等待receive_messages线程通知
    # print_event.clear()  # 清除事件，以便下一次使用
    time.sleep(0.5)
    message = input()
    if message.startswith("/msgto"):
        parts = message.split(" ", 2)
        if len(parts) < 3:
            print("\n> Error. Invalid /msgto command format. Usage: /msgto [recipient] [message]\n")
            print(COMMAND_PROMPT)
            continue

    elif message.startswith("/activeuser"):
        if message.strip() != "/activeuser":
            print("\n> Error. Invalid /activeuser command format. Usage: /activeuser\n")
            print(COMMAND_PROMPT)
            continue

    elif message.startswith("/logout"):
        if message.strip() != "/logout":
            print("\n> Error. Invalid /logout command format. Usage: /logout\n")
            print(COMMAND_PROMPT)
        else:
            print(f"\n> Bye, {username}!")
            client_socket.sendall(message.encode())
            logout_event.wait()  # 等待服务器确认登出消息
            break  # 退出循环，终止程序

    elif message.startswith("/creategroup"):
        parts = message.split()
        if len(parts) < 2:
            print("\n> Error. Invalid /creategroup command format. Usage: /creategroup [group_name]\n")
            print(COMMAND_PROMPT)
            continue

    elif message.startswith("/joingroup"):
        parts = message.split()
        if len(parts) != 2:
            print("\n> Error. Invalid /joingroup command format. Usage: /joingroup [group_name]\n")
            print(COMMAND_PROMPT)
            continue

    elif message.startswith("/groupmsg"):
        parts = message.split(" ", 2)
        if len(parts) < 3:
            print("\n> Error. Invalid /groupmsg command format. Usage: /groupmsg [group_name] [message]\n")
            print(COMMAND_PROMPT)
            continue

    elif message.startswith("/p2pvideo"):
        # 添加 /p2pvideo 命令的格式验证
        print('not finished')

    else:
        print("\n> Error. Invalid command!\n")
        print(COMMAND_PROMPT)
        continue
    client_socket.sendall(message.encode())

    if message.startswith("/msgto"):
        
        try:
            _, recipient, content = message.split(" ", 2)
            # print(f"\n> {time.strftime('%d %b %Y %H:%M:%S')}, {username} message to {recipient}: “{content}”.")
        except IndexError:
            print("> Error. Invalid /msgto command format.")
    elif message.startswith("/activeuser"):
        
        pass  # 服务器会处理这个命令并在receive_messages函数中显示活跃的用户
    elif message.startswith("/logout"):
        
        print(f"\n> Bye, {username}!")
        logout_event.wait()  # 等待receive_messages线程设置事件
        client_socket.close()  # 关闭套接字以结束receive_messages线程
        break
    elif message.startswith("/p2pvideo"):
        # 这里处理/p2pvideo的逻辑
        print('not finished')
    elif message.startswith("/creategroup"):
        
        try:
            time.sleep(0.5)
            _, group_name, *members = message.split()
            response = f"/creategroup {group_name} {username} {' '.join(members)}"
            # client_socket.sendall(response.encode())
        except ValueError:
            print("> Error. Invalid /creategroup command format.")
    elif message.startswith("/joingroup"):
        
        try:
            time.sleep(0.5)
            _, group_name = message.split()
            response = f"/joingroup {group_name}"
            # client_socket.sendall(response.encode())
        except ValueError:
            print("> Error. Invalid /joingroup command format.")
    elif message.startswith("/groupmsg"):
        
        try:
            time.sleep(0.5)
            _, group_name, content = message.split(" ", 2)
            response = f"/groupmsg {group_name} {content}"
            # client_socket.sendall(response.encode())
            # print("\n>Group chat message sent.\n")
            # print(COMMAND_PROMPT)
        except ValueError:
            print("> Error. Invalid /groupmsg command format.")
    else:
        print("\n> Error. Invalid command!")

    


# 我们在这里不再使用sleep，而是直接在循环的结尾再次显示提示符，除非遇到/logout命令

client_socket.close() 