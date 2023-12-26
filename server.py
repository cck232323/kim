import socket
import threading
import sys
import ast
import datetime
import logging
import re

logging.basicConfig(filename='userlog.txt', level=logging.INFO, format='%(message)s')

if len(sys.argv) != 3:
    print("\n===== Error usage, python3 Server.py SERVER_PORT NUMBER_OF_CONSECUTIVE_FAILED_ATTEMPTS ======\n")
    exit(0)

server_host = "127.0.0.1"
server_port = int(sys.argv[1])
number_of_consecutive_failed_attempts = int(sys.argv[2])

# Check the validity of number_of_consecutive_failed_attempts
if not isinstance(number_of_consecutive_failed_attempts, int) or not 1 <= number_of_consecutive_failed_attempts <= 5:
    print(
        "Invalid number of allowed failed consecutive attempt: {}. The valid value of argument number is an integer between 1 and 5".format(
            number_of_consecutive_failed_attempts))
    exit(0)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_host, server_port))

# 用户和群组信息
users = {}  # Store user information
groups = {}  # Store group information

class ClientThread(threading.Thread):
    failed_username_attempts = {}  # {username: count_of_failed_username_attempts}
    failed_password_attempts = {}
    failed_attempts = {}  # {username: count_of_failed_attempts}
    blocked_users = {}  # {username: block_end_time}
    active_clients = {}
    group_info = {}
    def __init__(self, client_address, client_socket):
        threading.Thread.__init__(self)
        self.client_address = client_address
        self.client_socket = client_socket
        self.username = None
        self.logout_event = threading.Event()
        self.active_clients = {}
        print("===== New connection added: ", client_address)

    def run(self):
        for user in ClientThread.active_clients.keys():
            print(f"> {user} is online")
        try:
            while True:
                data = self.client_socket.recv(1024)
                message = data.decode()
                if self.logout_event.is_set():
                    print("===== User logout - ", self.client_address)
                    break
                if message == '':
                    if self.username and self.username in ClientThread.active_clients:
                        del ClientThread.active_clients[self.username]
                    print("===== User disconnected - ", self.client_address)
                    break
                elif 'username' in message and 'password' in message:
                    credentials = ast.literal_eval(message)
                    self.process_login(credentials)
                elif message.startswith("/msgto "):
                    self.process_msgto(message)
                elif message == "/activeuser":
                    self.process_activeuser()
                elif message.startswith("/logout"):
                    self.process_logout()
                    break
                elif message.startswith("/creategroup"):
                    _, groupname, *members = message.split()
                    response = self.create_group(groupname, self.username, members)
                    self.client_socket.send(response.encode())
                elif message.startswith("/joingroup"):
                    groupname = message.split()[-1]
                    response = self.join_group(groupname, self.username)
                    self.client_socket.send(response.encode())
                elif message.startswith("/groupmsg"):
                    _, groupname, content = message.split(" ", 2)
                    self.process_group_message(groupname, self.username, content)
                elif message.startswith("/getudp"):
                    self.process_getudp(message)    
                else:
                    print("[recv] ", message)
                    self.client_socket.send(message.encode())
        except Exception as e:
            print("Connection error:", e)
        finally:
            if self.username and self.username in ClientThread.active_clients:
                del ClientThread.active_clients[self.username]
            print("===== User disconnected - ", self.client_address)

    def process_login(self, credentials):
        username = credentials["username"]

        if username in self.blocked_users:
            block_end_time = self.blocked_users[username]
            if datetime.datetime.now() < block_end_time:
                message = "Your account is blocked due to multiple login failures. Please try again later."
                self.client_socket.send(message.encode())
                return
            else:
                del self.blocked_users[username]
                self.failed_attempts.pop(username, None)

        with open("credentials.txt", "r") as file:
            valid_credentials = [line.strip().split(" ") for line in file.readlines()]

        valid_usernames = [cred[0] for cred in valid_credentials]

        is_valid_credentials = [credentials["username"], credentials["password"]] in valid_credentials

        if not is_valid_credentials:
            self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1

            if self.failed_attempts.get(username, 0) >= number_of_consecutive_failed_attempts:
                block_end_time = datetime.datetime.now() + datetime.timedelta(seconds=10)
                self.blocked_users[username] = block_end_time
                message = "Your account is blocked due to multiple login failures. Please try again later."
            elif username not in valid_usernames:
                message = "Invalid Username. Please try again."
            else:
                message = "Invalid Password. Please try again."
        else:
            self.username = credentials["username"]
            # 记录用户的 TCP 连接
            ClientThread.active_clients[self.username] = self
            message = "Authentication successful"
            self.client_socket.send(message.encode())
            
            # 接收用户的 UDP 端口
            udp_port = self.client_socket.recv(1024).decode()
            timestamp = datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')
            client_ip = self.client_address[0]
            
            # 记录到日志
            logging.info(f"{timestamp}; {username}; {client_ip}; {udp_port}")
            
            # 在这里记录用户的 IP 和 UDP 端口信息
            users[self.username] = {'ip': client_ip, 'udp_port': int(udp_port)}
            
            self.failed_attempts.pop(username, None)

        self.client_socket.send(message.encode())

    def process_msgto(self, message):
        try:
            _, recipient, content = message.split(" ", 2)
        except ValueError:
            error_msg = "> Error. Invalid command!"
            self.client_socket.send(error_msg.encode())
            return

        timestamp = datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')
        if recipient == self.username:  # 检查是否尝试给自己发送消息
            error_msg = "> Error. You cannot send a message to yourself."
            self.client_socket.send(error_msg.encode())
            return
        with open("messagelog.txt", "a") as file:
            message_number = sum(1 for _ in open('messagelog.txt')) + 1
            file.write(f"{message_number}; {timestamp}; {recipient}; {content}\n")

        if recipient in ClientThread.active_clients:
            recipient_socket = ClientThread.active_clients[recipient]
            # recipient_socket = recipient_thread.client_socket
            forward_msg = f"{timestamp}, {self.username}: {content}"
            recipient_socket.client_socket.send(forward_msg.encode())

            # 打印私信发送信息
            print(f"> {self.username} message to {recipient} “{content}” at {timestamp}")

            if recipient != self.username:
                confirmation_msg = f"> message sent at {timestamp}."
                self.client_socket.send(confirmation_msg.encode())
        else:
            error_msg = f"{recipient} is not an active user."
            self.client_socket.send(error_msg.encode())


    def process_activeuser(self):
        if not self.username:
            self.client_socket.send("Please login first.".encode())
            return

        active_users_info = []

        for user, client_sock in ClientThread.active_clients.items():
            if user != self.username:
                user_log_entry = [line for line in open('userlog.txt', 'r').readlines() if f"; {user};" in line][-1]
                timestamp, _, client_ip, udp_port = user_log_entry.split('; ')
                active_user_message = f"{user}, active since {timestamp}."
                active_users_info.append(active_user_message)

        # 打印用户使用 /activeuser 命令的信息
        print(f"> {self.username} issued /activeuser command")

        if active_users_info:
            full_message = "\n".join(active_users_info) + "\n"
            # 打印返回的活跃用户信息
            print("Return messages:\n" + full_message)
        else:
            full_message = "no other active user\n"
            print("Return messages:\n" + full_message)

        self.client_socket.send(full_message.encode())

    
    def create_group(self, groupname, creator, members):
        print(f"> {creator} issued /creategroup command")
    # 验证群组名称是否有效
        if not re.match("^[A-Za-z0-9]+$", groupname):
            return "Invalid group name. Only letters and digits are allowed."

        # 检查群组是否已存在
        if groupname in ClientThread.group_info:
            return f"A group chat (Name: {groupname}) already exists."

        # 检查是否有其他成员加入（除了创建者）
        if not members:
            return "Creation failed. Please add at least one member other than the creator."
        non_active_members = [member for member in members if member not in ClientThread.active_clients]
        if non_active_members:
            print(f"Creation failed. These users are not active: {', '.join(non_active_members)}")
            return "Creation failed. All users must be active to create a group."
        # 创建群组
        ClientThread.group_info[groupname] = {"members": [creator] + members, "creator": creator}
        with open(f"{groupname}_messagelog.txt", "w") as file:
            file.write("")

        response_message = f"Group chat room has been created, room name: {groupname}, users in this room: {' '.join(members)}" if members else "Group chat room is not created. Please enter at least one more active users."
        print("> Return message:\n" + response_message)

        return response_message
    def join_group(self, groupname, member):
        print(f"> {member} issued /joingroup command")
        if groupname not in ClientThread.group_info:
            return f"Group chat (Name: {groupname}) does not exist."

        if member not in ClientThread.group_info[groupname]["members"]:
            return f"You are not allowed to join group chat (Name: {groupname})."

        # 初始化 joined_members 列表（如果还不存在）
        if 'joined_members' not in ClientThread.group_info[groupname]:
            ClientThread.group_info[groupname]['joined_members'] = []

        # 将成员添加到 joined_members 列表（如果他们还不在列表中）
        if member not in ClientThread.group_info[groupname]['joined_members']:
            ClientThread.group_info[groupname]['joined_members'].append(member)

        response_message = f"You have joined group chat (Name: {groupname})." if member in ClientThread.group_info[groupname]["members"] else "Join group chat room successfully, room name: {groupname}, users in this room: {' '.join(ClientThread.group_info[groupname]['members'])}"
        print(f"> Return message:\n{member}, " + response_message)

        return response_message

    def send_group_message(self, groupname, sender, content):
        if groupname not in ClientThread.groups:
            return "The group chat does not exist."

        if sender not in ClientThread.groups[groupname]["members"]:
            return f"You are not in this group chat (Name: {groupname})."

        timestamp = datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')
        message_number = sum(1 for line in open(f'{groupname}_messagelog.txt')) + 1
        with open(f"{groupname}_messagelog.txt", "a") as file:
            print("write to file")
            file.write(f"{message_number}; {timestamp}; {groupname}; {sender}: {content}\n")

        for member in ClientThread.groups[groupname]["members"]:
            if member in ClientThread.active_clients and member != sender:
                recipient_socket = ClientThread.active_clients[member]
                forward_msg = f"[{groupname}] {timestamp}, {sender}: {content}"
                recipient_socket.client_socket.send(forward_msg.encode())
        print("send to all members")
        return f"Group message sent at {timestamp} to {groupname}: {content}"

    def process_group_message(self, groupname, sender, content):
        print(f"> {sender} issued /groupmsg command in {groupname}")
        if groupname in ClientThread.group_info:
            # 检查发消息的用户是否已经加入群组
            if sender in ClientThread.group_info[groupname].get("joined_members", []):
                timestamp = datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')

                # 写入群消息日志文件
                message_number = sum(1 for line in open(f'{groupname}_messagelog.txt')) + 1
                with open(f"{groupname}_messagelog.txt", "a") as file:
                    file.write(f"{message_number}; {timestamp}; {groupname}; {sender}: {content}\n")

                # 转发消息给群组其他成员
                message = f"{timestamp},{groupname}, {sender}: {content}"
                for member in ClientThread.group_info[groupname]["members"]:
                    if member in ClientThread.active_clients and member != sender:
                        member_socket = ClientThread.active_clients[member]
                        member_socket.client_socket.send(message.encode())  # 使用正确的socket对象发送消息

                # 向发送者发送确认消息
                print(f"{datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')}; {groupname}; {sender}; {content}")
                confirmation_msg = ">Group chat message sent"
                self.client_socket.send(confirmation_msg.encode())  # 使用正确的socket对象发送确认消息
            else:
                error_msg = "Please join the group before sending messages."
                self.client_socket.send(error_msg.encode())  # 使用正确的socket对象发送错误消息
                print("> Return message:\n" + error_msg)
        else:
            error_msg = "The group chat does not exist."
            self.client_socket.send(error_msg.encode())  # 使用正确的socket对象发送错误消息
            print("> Return message:\n" + error_msg)
        
    def process_logout(self):
        if self.username and self.username in ClientThread.active_clients:
            del ClientThread.active_clients[self.username]  # 从活跃用户列表中移除
            print(f"{self.username} has logged out.")  # 在服务器控制台打印登出信息

        self.logout_event.set()  # 设置登出事件标志

        logging.info(f"{datetime.datetime.now().strftime('%d %b %Y %H:%M:%S')}; {self.username}; logged out.")  # 记录到日志
        self.client_socket.send("You have successfully logged out.".encode())  # 发送登出确认给客户端

    def process_getudp(self, message):
        _, target_username = message.split()
        
        # 检查目标用户是否在线并且有 UDP 端口信息
        if target_username in ClientThread.active_clients and target_username in users:
            # 获取目标用户的 UDP 端口
            target_udp_port = users[target_username]['udp_port']
            target_ip = users[target_username]['ip']
            response = f"{target_ip},{target_udp_port}"
        else:
            response = "Error: User not active or UDP port not set."
        
        # 发送响应回客户端
        self.client_socket.send(response.encode())

def start_server():
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_host, server_port))
    print("\n===== Server is running =====")
    print("===== Waiting for connection requests from clients...=====")

    while True:
        server_socket.listen(1)
        client_sock, client_addr = server_socket.accept()
        client_thread = ClientThread(client_addr, client_sock)
        client_thread.start()

if __name__ == "__main__":
    start_server()     