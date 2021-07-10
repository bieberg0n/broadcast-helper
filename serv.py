import socket
from scapy.all import send, Raw, RandShort, sr1, conf, L3RawSocket, sniff
from scapy.layers.inet import IP, UDP, Ether
import json5


def log(*args):
	print(*args)


class Server:
	def __init__(self):
		with open('./config.json5') as f:
			self.cfg = json5.loads(f.read())

	def parse(self, data):
		sport = int.from_bytes(data[0:2], byteorder='big')
		dport = int.from_bytes(data[2:4], byteorder='big')
		payload = data[4:]
		return sport, dport, payload

	def handle(self, data, addr):
		sport, dport, payload = self.parse(data)
		src_ip, _p = addr
		dsts = [i for i in self.cfg['broadcast_list'] if i != src_ip]
		for dst in dsts:
			send(IP(src=src_ip, dst=dst) / UDP(sport=sport, dport=dport) / payload)
			log(f'{src_ip}:{sport} -> {dst}:{dport} len: {len(payload)}')

	def run(self):
		if self.cfg['debug']:
			conf.L3socket = L3RawSocket
		listen_ip = self.cfg['server_ip']
		listen_port = self.cfg['server_port']

		s = socket.socket(2, 2)
		s.bind((listen_ip, listen_port))
		log(f'listen on: {listen_ip}:{listen_port}')

		while True:
			data, addr = s.recvfrom(4096)
			self.handle(data, addr)


def main():
	s = Server()
	s.run()


if __name__ == '__main__':
	main()
