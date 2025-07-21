import socket, random
from config import BS_IP, BS_PORT
import utils

class BootstrapServer:
    def __init__(self):
        self.nodes = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((BS_IP, BS_PORT))
        print(f"Bootstrap server listening on {BS_IP}:{BS_PORT}")

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                msg = utils.unpack_msg(data)
                parts = msg.split()
                cmd = parts[0]

                if cmd == 'REG' and len(parts) == 4:
                    ip, port, uname = parts[1:]
                    print(f"[Bootstrap] Node joined: {uname} ({ip}:{port})")
                    entry = (ip, int(port), uname)
                    if entry not in self.nodes:
                        self.nodes.append(entry)
                        ok = self.nodes.copy()
                        no = len(ok) - 1
                        payload = f"REGOK {no}"
                        for node in ok[:-1]:
                            payload += f" {node[0]} {node[1]}"
                        self.sock.sendto(utils.pack_msg(payload), addr)
                    else:
                        self.sock.sendto(utils.pack_msg("REGOK 9998"), addr)

                elif cmd == 'UNREG' and len(parts) == 4:
                    ip, port, uname = parts[1:]
                    entry = (ip, int(port), uname)
                    if entry in self.nodes:
                        self.nodes.remove(entry)
                        self.sock.sendto(utils.pack_msg("UNROK 0"), addr)
                        print(f"[Bootstrap] Node left: {uname} ({ip}:{port})")
                    else:
                        self.sock.sendto(utils.pack_msg("UNROK 9999"), addr)

                elif cmd == 'PRINT':
                    for n in self.nodes:
                        print(n)
                    self.sock.sendto(utils.pack_msg(""), addr)

                # elif cmd == 'FIND' and len(parts) == 2:
                #     find_id = int(parts[1])
                #     if self.nodes:
                #         node = random.choice(self.nodes)
                #         ip, port, uname = node
                #         # Bootstrap doesn’t know real IDs, so send 0 for node ID
                #         reply = f"FNDOK 0 {ip} {port}"
                #         self.sock.sendto(utils.pack_msg(reply), addr)
                #         print(f"[Bootstrap] FIND {find_id} responded with {ip}:{port}")
                #     else:
                #         self.sock.sendto(utils.pack_msg("FNDERR No nodes"), addr)

                else:
                    self.sock.sendto(utils.pack_msg("ERROR"), addr)

            except Exception as e:
                print(f"[Bootstrap] Error: {e}")
                continue

if __name__ == "__main__":
    BootstrapServer().run()
