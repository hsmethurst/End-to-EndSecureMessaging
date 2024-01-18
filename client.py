import socket
import select
import Crypto.Util.number
import getpass as gp
import errno
from threading import Thread
import sys
from types import CodeType
import json
import utility_functions.message_cipher as cipher
from PIL import Image
from os import system, name
import os
from time import sleep

HEADER_LENGTH = 10
TYPE_LENGTH = 25

# Header of each filed defines the size of the message itself (integer)
# Type defines either the destination via username or a string of what that client is requesting
# if type == 'list_users', the server should send back the list_users output

IP = "127.0.0.1"
PORT = 1234

commands = ['!help','!exit','!back','!refresh','!deleteacc','!deletehist','!history']


def clear() -> int:
	"""
	Clears terminal window for cleaner viewing
	"""
	# for windows
	if name == 'nt':
		system_return = system('cls')
	else:     # for mac and linux(here, os.name is 'posix')
		system_return = system('clear')
	return system_return

class Client:
	def __init__(self) -> None:
		self.login()
		clear()
		
		# dict of keys, user as "key", secret_key as "value"
		self.keys = {}
		
		self.connection_established = 0
		self.main_loop()

	def main_loop(self):
		while True:
			try:
				self.send_message()
			except KeyboardInterrupt as e:
				response = input("\nDo you want to exit? (y/n)\n")
				if response == 'y':
					self.exit()
			
			else:
				self.receive_messages()
	
	def login(self) -> str:
		# Create a socket
		self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# Connect to a given ip and port
		self.client_socket.connect((IP, PORT))
		# Set connection to non-blocking state, so .recv() call won't block, just return some exception we'll handle
		self.client_socket.setblocking(False)
		# Prepare username and header and send them
		# We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well
		##Check if the user is new or existing
		while True:
			user_status = input("Have an account? (Y/N): ")
			if user_status in ('y','Y','N','n'):
				break
			else:
				print("\nInvalid response\n")

		## New user, so add an account to the database
		if user_status.upper() == 'N':
			while True:
				self.username = input("Choose a username: ")
				if len(self.username) > 20:
					print("Username must be less than 20 characters\n")
				elif len(self.username) == 0:
					print("You entered nothing\n")
				else:
					while True:
						passwd = gp.getpass(prompt='Choose a password: ', stream=None)
						if len(passwd) > 20:
							print("Password must be less than 20 characters\n")
						elif len(passwd) == 0:
							print("You entered nothing\n")
						else:
							confirm_passwd = gp.getpass(prompt='Enter your password again: ', stream=None)
							if confirm_passwd != passwd:
								print("Passwords do not match\n")
							else:
								break
							
				self.username_encoded = self.username.encode('utf-8')
				self.username_header = f"{len(self.username_encoded):<{HEADER_LENGTH}}".encode('utf-8')
				self.username_type = f"{'newuser':<{TYPE_LENGTH}}".encode('utf-8')
				password_encoded = passwd.encode('utf-8')
				password_header = f"{len(password_encoded):<{HEADER_LENGTH}}".encode('utf-8')
				password_type = f"{'password':<{TYPE_LENGTH}}".encode('utf-8')
				self.client_socket.send(self.username_header + self.username_type + self.username_encoded + password_header + password_type + password_encoded)
				sleep(1)
				response = self.recieve_single_message()

				if response=='True':
					print("Account created\n")
					sleep(1)
					return
				else:
					print("Username taken")
					self.login()
					break
		elif user_status.upper() == 'Y':
			while True:
				self.username = input("Username: ")
				passwd = gp.getpass(prompt='Password: ', stream=None)
				self.username_encoded = self.username.encode('utf-8')
				self.username_header = f"{len(self.username_encoded):<{HEADER_LENGTH}}".encode('utf-8')
				self.username_type = f"{'username':<{TYPE_LENGTH}}".encode('utf-8')
				password_encoded = passwd.encode('utf-8')
				password_header = f"{len(password_encoded):<{HEADER_LENGTH}}".encode('utf-8')
				password_type = f"{'password':<{TYPE_LENGTH}}".encode('utf-8')
				self.client_socket.send(self.username_header + self.username_type + self.username_encoded + password_header + password_type + password_encoded)
				sleep(1)
				response = self.recieve_single_message()
				if response=='True':
					print("Login successful\n")
					sleep(1)
					return
				else:
					print("Username or password was not correct\n")
					self.login()
					break
	
	def exit(self):
		print("Exiting")
		self.client_socket.close()
		sys.exit(1)

	def request_online_users(self):
		clear()
		emptyMessage = "".encode('utf-8')
		request_header = f"{0:<{HEADER_LENGTH}}".encode('utf-8')
		request_type = f"{'list_users':<{TYPE_LENGTH}}".encode('utf-8')
		self.client_socket.send(self.username_header + self.username_type + self.username_encoded + request_header + request_type + emptyMessage)
		sleep(0.1)
		self.receive_messages()

	def request_message_history(self):
		if self.destination_user:
			message_data = self.destination_user.encode('utf-8')
			request_header = f"{len(message_data):<{HEADER_LENGTH}}".encode('utf-8')
			request_type = f"{'history':<{TYPE_LENGTH}}".encode('utf-8')
			self.client_socket.send(self.username_header + self.username_type + self.username_encoded + request_header + request_type + message_data)
			sleep(0.1)
			self.receive_messages()
		else:
			print("Open a chat to view history")

	def request_del_message_history(self):
		if self.destination_user:
			message_data = self.destination_user.encode('utf-8')
			request_header = f"{len(message_data):<{HEADER_LENGTH}}".encode('utf-8')
			request_type = f"{'deletehist':<{TYPE_LENGTH}}".encode('utf-8')
			self.client_socket.send(self.username_header + self.username_type + self.username_encoded + request_header + request_type + message_data)
			sleep(0.1)
			self.receive_messages()
		else:
			print("Open a chat to delete history")

	def request_del_account(self):
		message_data = self.destination_user.encode('utf-8')
		request_header = f"{len(message_data):<{HEADER_LENGTH}}".encode('utf-8')
		request_type = f"{'deleteacc':<{TYPE_LENGTH}}".encode('utf-8')
		self.client_socket.send(self.username_header + self.username_type + self.username_encoded + request_header + request_type + message_data)
		sleep(0.1)
		self.receive_messages()

	def command_handler(self, message):
		if message=='!exit':
			self.exit()
		elif message=='!back':
			self.connection_established = 0
			self.destination_user = None
			clear()
		elif message=='!home':
			self.connection_established = 0
			self.destination_user = None
			clear()
		elif message=='!refresh':
			self.request_online_users()
		elif message=='!help':
			for command in commands:
				print(command)
		elif message=='!deleteacc':
			response = input("\nDo you want to delete your account? (y/n)\n")
			if response == 'y':
				self.request_del_account()
				
		elif message=='!history':
			self.request_message_history()
		elif message=='!deletehist':
			self.request_del_message_history()
		elif message=='!image':
			self.send_image()
		else:
			print('Command does not exist.')
			for command in commands:
				print(command)
	
	def establish_key(self):
		print("Waiting for", self.destination_user, "to join the chatroom")
		print("Enter Control + C once to go the homepage")
	
		# establish key using diffie hellman
		self.connection_established = 0
		
		# send user (to establish key with) to the server
		message = self.destination_user.encode('utf-8')
		
		# message type = 'establish'
		message_type = f"{'establish':<{TYPE_LENGTH}}".encode('utf-8')
		self.send_package(message, message_type)
		
		
		# receive g from the other client
		g = 0
		
		while 1:
			g = self.receive_messages()
			if g:
				g = int(g)
				break
		
		# generate p with 1024 bits and send
		p = 0
		
		p = Crypto.Util.number.getPrime(768)
		message = str(p).encode('utf-8')
		message_type = f"{self.destination_user:<{TYPE_LENGTH}}".encode('utf-8')
		self.send_package(message, message_type)
		
		# get confirmation
		confirmation = 0
		
		while 1:
			confirmation = self.receive_messages()
			if confirmation:
				confirmation = int(confirmation)
				break
			
		# generate a with 
		a = 0
		
		a = Crypto.Random.get_random_bytes(3)
		a = int.from_bytes(a, byteorder='big')

		# calculate a_mod to send to the other user
		a_mod = 0
		a_mod = self.modular_pow(g, a, p)

		message = str(a_mod).encode('utf-8')
		message_type = f"{self.destination_user:<{TYPE_LENGTH}}".encode('utf-8')
		self.send_package(message, message_type)
		
		# receive b_mod from the other client
		b_mod = 0
		
		while 1:
			b_mod = self.receive_messages()
			if b_mod:
				b_mod = int(b_mod)
				break
		
		
		# calculate key
		# key = (b_mod ** a) % p
		
		key = 0
		
		# key should be 256 bit
		key = (self.modular_pow(b_mod, a, p) % (2 ** 256)).to_bytes(32, byteorder='big')

		return key
		
	def receive_key(self):
		print(f"{self.destination_user} is in chatroom, loading in now...")
	
		self.connection_established = 0
		
		# is 1 byte enough?
		g = 0
		
		while g == 0:
			g = Crypto.Random.get_random_bytes(1)
			g = int.from_bytes(g, byteorder='big')

		message = str(g).encode('utf-8')
		message_type = f"{self.destination_user:<{TYPE_LENGTH}}".encode('utf-8')
		self.send_package(message, message_type)
		
		# receive p from the other client
		p = 0
		
		while 1:
			p = self.receive_messages()
			if p:
				p = int(p)
				break
			
		
		# confirm p
		message = str(p).encode('utf-8')
		self.send_package(message, message_type)
		
		# receive a_mod from the other client
		a_mod = 0
		
		while 1:
			a_mod = self.receive_messages()
			if a_mod:
				a_mod = int(a_mod)
				break
			
		
		# generate b with 256 bits
		b = 0
		
		b = Crypto.Random.get_random_bytes(3)
		b = int.from_bytes(b, byteorder='big')
		
		# calculate b_mod to send to the other user
		b_mod = 0
		
		
		b_mod = self.modular_pow(g, b, p)


		message = str(b_mod).encode('utf-8')
		message_type = f"{self.destination_user:<{TYPE_LENGTH}}".encode('utf-8')
		self.send_package(message, message_type)
		
		# calculate key
		# key = (b_mod ** a) % p
		
		key = 0
		
		# key should be 256 bit
		key = (self.modular_pow(a_mod, b, p) % (2 ** 256)).to_bytes(32, byteorder='big')
		return key

	def modular_pow(self, base, exponent, modulus):
		if modulus == 1:
			return 0
		c = 1
		for e_prime in range(0, exponent-1):
			if e_prime % 1000000 == 0:
				print("Loading...")
			c = (c * base) % modulus
		return c

	def send_message(self):
		if self.connection_established:
			# Wait for user to input a message
			message = input(f'{self.username} > ')

			# If message is not empty - send it
			if message:
				# Encode message with key, then encrypt to bytes, prepare header and convert to bytes, like for username above, then send
				# we do not want to encrypt the commands as the server needs to see them
				if message[0] != '!':
					message = cipher.get_encrypt_msg(message, self.keys[self.destination_user])
				message = message.encode('utf-8')
				message_type = f"{self.destination_user:<{TYPE_LENGTH}}".encode('utf-8')
				self.send_package(message, message_type)
		
		else:
			self.request_online_users()
			
			self.destination_user = input(f'Send a message to: ')
			self.receive_messages()
			if self.destination_user not in commands:
				if self.destination_user != self.username:
					if not self.connection_established:
						if self.destination_user not in self.keys:
							self.keys[self.destination_user] = self.establish_key()
						self.connection_established = 1
						clear()
						print("Messaging", self.destination_user)
				else:
					print("Cannot send message to oneself")
					sleep(1) # to show the error message
			else: 
				self.command_handler(self.destination_user)

	def receive_messages(self):
		try:
			# Now we want to loop over received messages (there might be more than one) and print them
			while True:

				# Receive our "header" containing username length, it's size is defined and constant
				username_header = self.client_socket.recv(HEADER_LENGTH)
				username_type = self.client_socket.recv(TYPE_LENGTH).decode('utf-8')
				# If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
				if not len(username_header):
					print('Connection closed by the server')
					self.exit()

				# Convert header to int value
				username_length = int(username_header.decode('utf-8').strip())

				# Receive and decode username
				username = self.client_socket.recv(username_length).decode('utf-8')

				# Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
				message_header = self.client_socket.recv(HEADER_LENGTH)
				message_type = self.client_socket.recv(TYPE_LENGTH).decode('utf-8').strip()
				message_length = int(message_header.decode('utf-8').strip())
				message = self.client_socket.recv(message_length).decode('utf-8').strip()

				# Print message
				if message_type=='list_users':
					# list users command
					users = json.loads(message)
					print("Online Users:")
					for user in users['users']:
						print(user)
					print()
				elif message_type=='establish':
					# user wants to use Diffie-Hellman
					if not self.connection_established:
						self.destination_user = username
						if self.destination_user not in self.keys:
							self.keys[self.destination_user] = self.receive_key()
						self.connection_established = 1
						print(f"{username}")
						clear()
						print("Messaging", self.destination_user)
						return
				elif message_type=='image':
					self.receive_image()
				elif message_type=='history':
					messages = json.loads(message)
					print("History")
					print("_____________________")
					for key, message_data in messages.items():
						try:
							decrypted_message = cipher.get_decrypt_msg(message_data['message'], self.keys[self.destination_user])
							print(f"{message_data['user1']} > {decrypted_message}")
						except KeyboardInterrupt:
							sys.exit()
						except:
							pass
					print("_____________________")
				elif message_type=="deletehist":
					if message=="True":
						print(f"History between {self.username} and {self.destination_user} deleted")
					else:
						print(f"Deleting Error: History between {self.username} and {self.destination_user} not deleted")
				elif message_type=='deleteacc':
					print("Account Deleted.")
					print("Exiting...")
					sys.exit()
				elif self.connection_established:
					# message should be encrypted
					message = cipher.get_decrypt_msg(message, self.keys[self.destination_user])
					print(f'{username} > {message}')
					return message
				else:
					return message

		except IOError as e:
			# This is normal on non blocking connections - when there are no incoming data error is going to be raised
			# Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
			# We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
			# If we got different error code - something happened
			if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
				print('Reading error: {}'.format(str(e)))
				sys.exit()

			# We just did not receive anything
			return

		except Exception as e:
			# Any other exception - something happened, exit
			print('Reading error: {}'.format(str(e)))
			sys.exit()

	def send_package(self, message, message_type):
		message_header = f"{len(message):<{HEADER_LENGTH}}".encode('utf-8')

		if message.decode('utf-8')[0]=='!':
			self.command_handler(message.decode('utf-8'))
		else: 
			self.client_socket.send(message_header + message_type +  message)
	
	def recieve_single_message(self):
		"""
		Used for login
		"""
		message_header = self.client_socket.recv(HEADER_LENGTH)
		message_type = self.client_socket.recv(TYPE_LENGTH).decode('utf-8').strip()
		# If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
		if not len(message_header):
			print('Connection closed by the server')
			self.exit()

		# Convert header to int value
		message_length = int(message_header.decode('utf-8').strip())
		# Receive and decode username
		message_data = self.client_socket.recv(message_length).decode('utf-8').strip()
		return message_data
	def send_image(self):
		message = str(self.destination_user).encode('utf-8')
		message_type = f"{'image':<{TYPE_LENGTH}}".encode('utf-8')
		self.send_package(message, message_type)
		
		# receive confirmation from the other client
		confirmation= 0
		
		while 1:
			confirmation = self.receive_messages()
			if confirmation:
				break
		
		if confirmation == 'ready to receive image':	
			
			print("Images:")
			self.get_image()
		
			path = 'images/' + input(f'image path: ')
			
			# encrypt image and send to other client
			cipher.get_encrypted_img(path, self.keys[self.destination_user])
			message_type = f"{self.destination_user:<{TYPE_LENGTH}}".encode('utf-8')
			self.send_package(message, message_type)
			
			# encrypt path and send to other client
			cipher.get_encrypt_msg(path, self.keys[self.destination_user]).encode('utf-8')
			message_type = f"{self.destination_user:<{TYPE_LENGTH}}".encode('utf-8')
			self.send_package(message, message_type)
		else:
			# error
			return

	def receive_image(self):
		print('receiving image')
		message = cipher.get_encrypt_msg('ready to receive image', self.keys[self.destination_user]).encode('utf-8')
		message_type = f"{self.destination_user:<{TYPE_LENGTH}}".encode('utf-8')
		self.send_package(message, message_type)
		
		print("sent confirmation")
		
		# receive image from the other client
		image= 0
		
		try:
			while True:
				sleep(10)
				print("hello world")
				# Receive our "header" containing username length, it's size is defined and constant
				username_header = self.client_socket.recv(HEADER_LENGTH)
				username_type = self.client_socket.recv(TYPE_LENGTH).decode('utf-8')
				# If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
				if not len(username_header):
					print('Connection closed by the server')
					self.exit()

				# Convert header to int value
				username_length = int(username_header.decode('utf-8').strip())

				# Receive and decode username
				username = self.client_socket.recv(username_length).decode('utf-8')

				# Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
				message_header = self.client_socket.recv(HEADER_LENGTH)
				message_type = self.client_socket.recv(TYPE_LENGTH).decode('utf-8').strip()
				message_length = int(message_header.decode('utf-8').strip())
				image = self.client_socket.recv(message_length).decode('utf-8')
				# image = cipher.get_decrypt_msg(image, self.keys[self.destination_user])
				if image:
					break
		except IOError as e:
			# This is normal on non blocking connections - when there are no incoming data error is going to be raised
			# Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
			# We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
			# If we got different error code - something happened
			if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
				print('Reading error: {}'.format(str(e)))
				sys.exit()

			# We just did not receive anything
			return

		except Exception as e:
			# Any other exception - something happened, exit
			print('Reading error: {}'.format(str(e)))
			sys.exit()
		
		print(image)
		
		# decrypt image and open
		image = cipher.get_decrypted_img(image, self.keys[self.destination_user])
		print(f"image received:{image}")
		
		# receive image from the other client
		path= 0
		
		while 1:
			path = self.receive_messages()
			if path:
				break
		
		self.open_image(path)
	
	''' Print out all the files available to send '''
	def get_image(self):
		for image in os.listdir('images'):
			print(image)

	''' Open the image '''
	def open_image(self, filename):
		img = Image.open(f'images/{filename}')
		img.show()    
	
	
client = Client()



			
			
