import socket
from scapy.all import send, Raw, RandShort, sr1, conf, L3RawSocket, sniff
from scapy.layers.inet import IP, UDP, Ether
import json5


# conf.L3socket=L3RawSocket


def log(*args):
	print(*args)


def port_to_bytes(n: int):
	return n.to_bytes(length=2, byteorder='big')


class Client:
	def __init__(self):
		with open('./config.json5') as f:
			cfg = json5.loads(f.read())
		self.serv_ip = cfg['server_ip']
		self.serv_port = cfg['server_port']
		self.s = socket.socket(2, 2)

	def prn(self, packet):
		sport = packet[UDP].sport
		dport = packet[UDP].dport
		log(f'catch: {packet[IP].src}:{sport} ->{packet[IP].dst}:{dport}')

		data = port_to_bytes(sport) + port_to_bytes(dport) + bytes(packet[UDP].payload)
		self.s.sendto(data, (self.serv_ip, self.serv_port))
		log(f'send to: {self.serv_ip}:{self.serv_port}, data len:{len(data)}')

	def run(self):
		f = 'dst net 255.255.255.255 and udp'
		log('sniff:', f)
		sniff(filter=f, prn=self.prn)


def main():
	c = Client()
	c.run()


if __name__ == '__main__':
	main()
