import socket
import select
import sys
import json
from user_database.user_handler import delete_history, show_history, add_history, check_user, create_user, delete_user
from time import sleep

HEADER_LENGTH = 10
TYPE_LENGTH = 25

# Header of each filed defines the size of the message itself (integer)
# Type defines either the destination via username or a string of what that client is requesting
# if type == 'list_users', the server should send back the list_users output

IP = "127.0.0.1"
PORT = 1234


class Server:
    def __init__(self) -> None:
        try:
            # Create a socket
            # socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
            # socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # SO_ - socket option
            # SOL_ - socket option level
            # Sets REUSEADDR (as a socket option) to 1 on socket
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind, so server informs operating system that it's going to use given IP and port
            # For a server using 0.0.0.0 means to listen on all available interfaces, useful to connect locally to 127.0.0.1 and remotely to LAN interface IP
            self.server_socket.bind((IP, PORT))

            print(f'Listening for connections on {IP}:{PORT}...')
            # This makes server listen to new connections
            self.server_socket.listen()

            # List of sockets for select.select()
            self.sockets_list = [self.server_socket]

            # List of connected clients - socket as a key, user header and name as data
            self.clients = {}
            self.listen()
        except KeyboardInterrupt:
            response = input("\nDo you want to exit? (y/n)\n")
            if response == 'y':
                print("Exiting")
                sys.exit(1)
    
    def cleanup_sockets(self) -> None:
        # It's not really necessary to have this, but will handle some socket exceptions just in case
        for notified_socket in self.exception_sockets:

            # Remove from list for socket.socket()
            self.sockets_list.remove(notified_socket)

            # Remove from our list of users
            del self.clients[notified_socket]

    def new_connection(self) -> None:
        # Accept new connection
        # That gives us new socket - client socket, connected to this given client only, it's unique for that client
        # The other returned object is ip/port set
        client_socket, client_address = self.server_socket.accept()

        # Client should send his name right away, receive it
        message = receive_initial_message(client_socket)
        if message:
            user = message[0]
            passwd = message[1]
        else:
            return

        # If False - client disconnected before he sent his name
        if user is False:
            return
        if user['type'].decode('utf-8').strip()=='username':
            status = check_user(user['data'].decode('utf-8').strip(), passwd['data'].decode('utf-8').strip())
            if status!=1:
                response_encoded = "False".encode('utf-8')
                response_header = f"{len(response_encoded):<{HEADER_LENGTH}}".encode('utf-8')
                response_type = f"{'response':<{TYPE_LENGTH}}".encode('utf-8')
                client_socket.send(response_header + response_type + response_encoded)
                return False
        
        elif user['type'].decode('utf-8').strip()=='newuser':
            insert_result = create_user(user['data'].decode('utf-8').strip(), passwd['data'].decode('utf-8').strip())
            print(insert_result)
            if not insert_result:
                response_encoded = "False".encode('utf-8')
                response_header = f"{len(response_encoded):<{HEADER_LENGTH}}".encode('utf-8')
                response_type = f"{'response':<{TYPE_LENGTH}}".encode('utf-8')
                client_socket.send(response_header + response_type + response_encoded)
                return False
        
        response_encoded = "True".encode('utf-8')
        response_header = f"{len(response_encoded):<{HEADER_LENGTH}}".encode('utf-8')
        response_type = f"{'response':<{TYPE_LENGTH}}".encode('utf-8')
        client_socket.send(response_header + response_type + response_encoded)
        sleep(1)
        # Add accepted socket to select.select() list
        self.sockets_list.append(client_socket)

        # Also save username and username header
        self.clients[client_socket] = user

        print('Accepted new connection from {}:{}, username: {}'.format(*client_address, user['data'].decode('utf-8')))
        self.list_users()
        return True
        
    def message_handler(self,notified_socket, message) -> None:
        # If False, client disconnected, cleanup
        if message is False:
            print('Closed connection from: {}'.format(self.clients[notified_socket]['data'].decode('utf-8')))
            # Remove from list for socket.socket()
            self.sockets_list.remove(notified_socket)
            # Remove from our list of users
            del self.clients[notified_socket]
            return

        # Get user by notified socket, so we will know who sent the message
        sending_user = self.clients[notified_socket]

        # connection_established = message["data"].decode("utf-8")[0] CHANGE THIS TO THE MESSAGE TYPE

        print(f'Received message from {sending_user["data"].decode("utf-8").strip()} - "{message["type"].decode("utf-8").strip()}": {message["data"].decode("utf-8").strip()}')
        sending_user_type = f"{'username':<{TYPE_LENGTH}}".encode('utf-8')
        # Iterate over connected clients and broadcast message
        if message['type'].decode('utf-8').strip()=='list_users':
            # Implement the list_users send now
            online_users = self.list_users().encode('utf-8')
            message_header = f"{len(online_users):<{HEADER_LENGTH}}".encode('utf-8')
            notified_socket.send(sending_user['header'] + sending_user_type + sending_user['data'] + message_header + message['type'] + online_users)
        elif message['type'].decode('utf-8').strip() == 'establish':
            print(f'establish connection {sending_user["data"].decode("utf-8").strip()} to {message["data"].decode("utf-8").strip()}')
            flag = False
            for client_socket in self.clients:
                if self.clients[client_socket]['data'].decode('utf-8').strip() == message['data'].decode('utf-8').strip():
                    client_socket.send(sending_user['header'] + sending_user_type + sending_user['data'] + message['header'] + message['type'] + message['data'])
                    flag = True
                    break
            if not flag:
                print('User',message['data'].decode('utf-8').strip(),'is not online.')
        elif message['type'].decode('utf-8').strip() == 'image':
            print(f'sending image {sending_user["data"].decode("utf-8").strip()} to {message["data"].decode("utf-8").strip()}')
            flag = False
            for client_socket in self.clients:
                if self.clients[client_socket]['data'].decode('utf-8').strip() == message['data'].decode('utf-8').strip():
                    client_socket.send(sending_user['header'] + sending_user_type + sending_user['data'] + message['header'] + message['type'] + message['data'])
                    flag = True
                    break
            if not flag:
                print('User',message['data'].decode('utf-8').strip(),'is not online.')
        elif message['type'].decode('utf-8').strip() == 'history':
            history = self.get_history(sending_user['data'].decode("utf-8").strip(), message['data'].decode("utf-8").strip()).encode('utf-8')
            message_header = f"{len(history):<{HEADER_LENGTH}}".encode('utf-8')
            notified_socket.send(sending_user['header'] + sending_user_type + sending_user['data'] + message_header + message['type'] + history)

        elif message['type'].decode('utf-8').strip() == 'deletehist':
            completed = str(delete_history(sending_user['data'].decode("utf-8").strip(), message['data'].decode("utf-8").strip())).encode('utf-8')
            message_header = f"{len(completed):<{HEADER_LENGTH}}".encode('utf-8')
            notified_socket.send(sending_user['header'] + sending_user_type + sending_user['data'] + message_header + message['type'] + completed)

        elif message['type'].decode('utf-8').strip() == 'deleteacc':
            completed = str(delete_user(sending_user['data'].decode("utf-8").strip())).encode('utf-8')
            message_header = f"{len(completed):<{HEADER_LENGTH}}".encode('utf-8')
            notified_socket.send(sending_user['header'] + sending_user_type + sending_user['data'] + message_header + message['type'] + completed)

        else:
            flag = False
            for client_socket in self.clients:
                if self.clients[client_socket]['data'].decode('utf-8').strip() == message['type'].decode('utf-8').strip():
                    client_socket.send(sending_user['header'] + sending_user_type + sending_user['data'] + message['header'] + message['type'] + message['data'])
                    add_history(sending_user['data'].decode('utf-8').strip(),message['type'].decode('utf-8').strip(),message['data'].decode('utf-8').strip())
                    flag = True
                    break
            if not flag:
                print('User',message['type'].decode('utf-8').strip(),'is not online.')

    def listen(self):
        while True:
            try:
                # Calls Unix select() system call or Windows select() WinSock call with three parameters:
                #   - rlist - sockets to be monitored for incoming data
                #   - wlist - sockets for data to be send to (checks if for example buffers are not full and socket is ready to send some data)
                #   - xlist - sockets to be monitored for exceptions (we want to monitor all sockets for errors, so we can use rlist)
                # Returns lists:
                #   - reading - sockets we received some data on (that way we don't have to check sockets manually)
                #   - writing - sockets ready for data to be send thru them
                #   - errors  - sockets with some exceptions
                # This is a blocking call, code execution will "wait" here and "get" notified in case any action should be taken

                self.read_sockets, _, self.exception_sockets = select.select(self.sockets_list, [], self.sockets_list)
              


                # Iterate over notified sockets
                for notified_socket in self.read_sockets:

                    # If notified socket is a server socket - new connection, accept it
                    if notified_socket == self.server_socket:
                        self.new_connection()
                    # Else existing socket is sending a message
                    else:
                        # Receive message
                        message = receive_message(notified_socket)
                        self.message_handler(notified_socket, message)
                        
                self.cleanup_sockets()
            except KeyboardInterrupt: # Keyboard interrupt only works on next time recieving a packet
                response = input("\nDo you want to exit? (y/n)\n")
                if response == 'y':
                    print("Exiting")
                    sys.exit(1)
    
    def list_users(self):
        """
        Returns JSON with key as username and data as socket
        """
        print("\nUsers Online:")
        users_online = {'users':[]}
        for socket, client in self.clients.items():
            users_online['users'].append(client['data'].decode('utf-8').strip())
            print(users_online['users'][-1])
        print()
        return json.dumps(users_online)

    def get_history(self, user1, user2):
        history = show_history(user1, user2)
        history_return = {}
        for entry in history:
            history_return[entry[0]]= {
                'user1': entry[1],
                'user2': entry[2],
                'message': entry[3],
                'timestamp': entry[4],
            }
        return json.dumps(history_return)

# Handles message receiving
def receive_message(client_socket):

    try:
        # Receive our "header" containing message length, it's size is defined and constant
        message_header = client_socket.recv(HEADER_LENGTH)
        message_type = client_socket.recv(TYPE_LENGTH)
        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not len(message_header):
            return False

        # Convert header to int value
        message_length = int(message_header.decode('utf-8').strip())

        # Return an object of message header and message data
        return {'header': message_header, 'type': message_type, 'data': client_socket.recv(message_length)}

    except KeyboardInterrupt:
        response = input("\nDo you want to exit? (y/n)\n")
        if response == 'y':
            print("Exiting")
            sys.exit(1)
    except: 
        # If we are here, client closed connection violently, for example by pressing ctrl+c on his script
        # or just lost his connection
        # socket.close() also invokes socket.shutdown(socket.SHUT_RDWR) what sends information about closing the socket (shutdown read/write)
        # and that's also a cause when we receive an empty message
        return False

def receive_initial_message(client_socket):

    try:
        # Receive our "header" containing message length, it's size is defined and constant
        message_header = client_socket.recv(HEADER_LENGTH)
        message_type = client_socket.recv(TYPE_LENGTH)
        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not len(message_header):
            return False

        # Convert header to int value
        message_length = int(message_header.decode('utf-8').strip())
        user = {'header': message_header, 'type': message_type, 'data': client_socket.recv(message_length)}
        # Receive our "header" containing message length, it's size is defined and constant
        message_header = client_socket.recv(HEADER_LENGTH)
        message_type = client_socket.recv(TYPE_LENGTH)
        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not len(message_header):
            return False

        # Convert header to int value
        message_length = int(message_header.decode('utf-8').strip())
        password = {'header': message_header, 'type': message_type, 'data': client_socket.recv(message_length)}


        # Return an object of message header and message data
        return user, password

    except KeyboardInterrupt:
        response = input("\nDo you want to exit? (y/n)\n")
        if response == 'y':
            print("Exiting")
            sys.exit(1)
    except: 
        # If we are here, client closed connection violently, for example by pressing ctrl+c on his script
        # or just lost his connection
        # socket.close() also invokes socket.shutdown(socket.SHUT_RDWR) what sends information about closing the socket (shutdown read/write)
        # and that's also a cause when we receive an empty message
        return False


server = Server()