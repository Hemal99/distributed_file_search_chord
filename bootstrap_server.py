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
                cmd = parts[1]

                if cmd == "REG" and len(parts) == 4:
                    ip, port, uname = parts[1:]
                    print(f"[Bootstrap] Node joined: {uname} ({ip}:{port})")
                    entry = (ip, int(port), uname)
                    if entry not in self.nodes:
                        self.nodes.append(entry)
                        ok = self.nodes.copy()
                        no = len(ok) - 1

                        if no > 2:
                            no = 2
                            ok = ok[:-1][:2]  # return only 2 nodes

                        payload = f"REGOK {no}"
                        for node in ok[:-1]:
                            payload += f" {node[0]} {node[1]}"
                        formatted_msg = utils.format_message(payload)
                        self.sock.sendto(utils.pack_msg(formatted_msg), addr)
                    else:
                        # Already registered
                        payload = utils.format_message("REGOK 9998")
                        self.sock.sendto(utils.pack_msg(payload), addr)

                elif cmd == "UNREG" and len(parts) == 4:
                    ip, port, uname = parts[1:]
                    entry = (ip, int(port), uname)
                    if entry in self.nodes:
                        self.nodes.remove(entry)
                        print(f"[Bootstrap] Node left: {uname} ({ip}:{port})")
                        payload = utils.format_message("UNROK 0")
                        self.sock.sendto(utils.pack_msg(payload), addr)
                    else:
                        payload = utils.format_message("UNROK 9999")
                        self.sock.sendto(utils.pack_msg(payload), addr)

                elif cmd == "PRINT":
                    for n in self.nodes:
                        print(n)
                    self.sock.sendto(utils.pack_msg(utils.format_message("")), addr)

                else:
                    self.sock.sendto(utils.pack_msg(utils.format_message("ERROR")), addr)

            except Exception as e:
                print(f"[Bootstrap] Error: {e}")
                continue


if __name__ == "__main__":
    BootstrapServer().run()
