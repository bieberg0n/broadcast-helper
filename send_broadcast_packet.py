import socket
from datetime import datetime


def log(*args):
	print(*args)


def main():
	s = socket.socket(2, 2)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
	now = str(datetime.now())
	data = b'A package, ' + bytes(now, 'utf-8')
	s.sendto(data, ('255.255.255.255', 5000))


if __name__ == '__main__':
	main()
