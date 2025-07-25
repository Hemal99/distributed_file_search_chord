import threading, time, socket, random
from config import *
from utils import sha1_hash, in_interval, pack_msg, unpack_msg,numeric_id, format_message
import file_service

class ChordNode:
    def __init__(self, ip, chord_port, rest_port, username):
        self.ip = ip
        self.chord_port = chord_port
        self.rest_port = rest_port
        self.username = username
        self.id = numeric_id(ip, chord_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.join_event = threading.Event()
        self.join_response = None
        self.sock.bind((ip, chord_port))

        # Consistent tuple order: (id, ip, port)
        self.successor = (self.id, self.ip, self.chord_port)
        self.predecessor = None
        self.finger = [(self.id, self.ip, self.chord_port)] * FINGER_SIZE

        # random 3–5 files
        with open("files.txt", "r") as f:
            pool = [line.strip() for line in f if line.strip()]  

        self.files = set(random.sample(pool, random.randint(3, 5)))
        self.running = True

        # stats
        self.stats = { 'sent':0, 'recv':0, 'fwd':0, 'ans':0 }

    def start(self):
        threading.Thread(target=self.udp_listener, daemon=True).start()
        threading.Thread(target=self.stabilize_loop, daemon=True).start()
        threading.Thread(target=self.fix_loop, daemon=True).start()
        threading.Thread(target=self.check_predecessor_loop, daemon=True).start()
        threading.Thread(target=file_service.start_rest, args=(self.rest_port,self), daemon=True).start()

        self.register_and_join()
        print(f"Node {self.username} ID {self.id} started. Files: {self.files}")

    def register_and_join(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        msg = f"REG {self.ip} {self.chord_port} {self.username}"
        sock.sendto(pack_msg(msg), (BS_IP, BS_PORT))
        resp, _ = sock.recvfrom(UDP_BUFFER)
        decoded = unpack_msg(resp)
        parts = decoded.split()

        if parts[1] != 'REGOK':
            print("BS error:", decoded)
            return

        no = parts[2]
        # Handle error codes explicitly:
        if no == '9998':
            print("[register_and_join] Bootstrap error: already registered")
            return
        elif no == '9999':
            print("[register_and_join] Bootstrap error: failed, please try again")
            return

        try:
            no_peers = int(no)
            peers = [(parts[i], int(parts[i + 1])) for i in range(2, 2 + 2 * no_peers, 2)]
        except Exception as e:
            print(f"[register_and_join] Error parsing peers: {decoded}, error: {e}")
            return

        if peers:
            peer = random.choice(peers)
            self.do_join(peer[0], peer[1])
        else:
            print("[register_and_join] No peers returned by bootstrap, starting new ring")

    def do_join(self, ip, port):
        self.join_response = None
        self.join_event.clear()

        msg = format_message(f"JOIN {self.id} {self.ip} {self.chord_port}")
        self.sock.sendto(pack_msg(msg), (ip, port))

        if self.join_event.wait(timeout=5):  
            if self.join_response and self.join_response[0] == 'SUCC':
                # Message format: SUCC <id> <ip> <port> -> parts[1], parts[2], parts[3]
                succ_id, succ_ip, succ_port = int(self.join_response[1]), self.join_response[2], int(self.join_response[3])
                self.successor = (succ_id, succ_ip, succ_port)
                print(f"Successor updated to: {self.successor}")
            elif self.join_response and self.join_response[0] == 'JOINOK' and self.join_response[1] == '0':
                self.successor = (numeric_id(ip, port), ip, port)
                print(f"Joined ring with initial successor: {self.successor}")
            else:
                print("JOIN failed: Unexpected response:", self.join_response)
        else:
            print("JOIN failed: timeout waiting for response")

    def udp_listener(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(UDP_BUFFER)
                msg = unpack_msg(data)
                parts = msg.split()
                cmd = parts[0]

                # Adjusting index for command parts due to length prefix (e.g., cmd is now parts[0])
                if cmd == 'FIND' and (len(parts) == 2 or len(parts) == 4):
                    find_id = int(parts[1])

                    if len(parts) == 4:
                        origin_ip = parts[2]
                        origin_port = int(parts[3])
                    else:
                        origin_ip, origin_port = addr[0], addr[1]  # fallback

                    if self.successor and in_interval(find_id, self.id, self.successor[0], inclusive_right=True):
                        reply = format_message(f"FNDOK {self.successor[0]} {self.successor[1]} {self.successor[2]}")
                        self.sock.sendto(pack_msg(reply), (origin_ip, origin_port))
                    else:
                        closest = self.closest_preceding_node(find_id)
                        if closest == (self.id, self.ip, self.chord_port):
                            reply = format_message(f"FNDOK {self.id} {self.ip} {self.chord_port}")
                            self.sock.sendto(pack_msg(reply), (origin_ip, origin_port))
                        else:
                            try:
                                msg = format_message(f"FIND {find_id} {origin_ip} {origin_port}")
                                self.sock.sendto(pack_msg(msg), (closest[1], closest[2]))
                            except Exception as e:
                                print(f"[udp_listener] Error forwarding FIND: {e}")

                elif cmd == 'FNDOK' and len(parts) == 4:
                    succ_id, succ_ip, succ_port = int(parts[1]), parts[2], int(parts[3])
                    if self.handle_find_ok:
                        self.handle_find_ok(succ_id, succ_ip, succ_port)

                elif cmd == 'JOIN' and len(parts) == 4:
                    node_id = int(parts[1])
                    node_ip = parts[2]
                    node_port = int(parts[3])
                    self.notify((node_id, node_ip, node_port))
                    # reply with our successor
                    succ_id, succ_ip, succ_port = self.successor
                    reply = format_message(f"SUCC {succ_id} {succ_ip} {succ_port}")
                    self.sock.sendto(pack_msg(reply), addr)

                elif cmd == 'NOTIFY' and len(parts) == 4:
                    pred_id = int(parts[1])
                    pred_ip = parts[2]
                    pred_port = int(parts[3])
                    self.notify((pred_id, pred_ip, pred_port))

                elif cmd == 'SUCC' and len(parts) == 4:
                    if self.join_response is None:
                        self.join_response = parts
                        self.join_event.set()
                    self.successor = (int(parts[1]), parts[2], int(parts[3]))
                    print(f"[udp_listener] Successor updated to: {self.successor}")

                elif cmd == 'JOINOK' and len(parts) >= 2:
                    if self.join_response is None:
                        self.join_response = parts
                        self.join_event.set()

                elif cmd == 'GETPRED':
                    if self.predecessor:
                        reply = format_message(f"RESPRED {self.predecessor[0]} {self.predecessor[1]} {self.predecessor[2]}")
                    else:
                        reply = format_message(f"RESPRED {self.id} {self.ip} {self.chord_port}")  # If no predecessor, reply with self
                    self.sock.sendto(pack_msg(reply), addr)

                elif cmd == 'RESPRED' and len(parts) == 4:
                    pred_id = int(parts[1])
                    pred_ip = parts[2]
                    pred_port = int(parts[3])
                    print(f"[udp_listener] Received RESPRED: {pred_id} {pred_ip} {pred_port}")

                elif cmd == 'UPDATE_SUCCESSOR' and len(parts) == 4:
                    new_succ_id = int(parts[1])
                    new_succ_ip = parts[2]
                    new_succ_port = int(parts[3])
                    self.successor = (new_succ_id, new_succ_ip, new_succ_port)
                    print(f"[{self.username}] Successor updated due to node departure: {self.successor}")

                elif cmd == 'UPDATE_PREDECESSOR' and len(parts) == 4:
                    new_pred_id = int(parts[1])
                    new_pred_ip = parts[2]
                    new_pred_port = int(parts[3])
                    self.predecessor = (new_pred_id, new_pred_ip, new_pred_port)
                    print(f"[{self.username}] Predecessor updated due to node departure: {self.predecessor}")

                elif cmd == 'SER' and len(parts) >= 5:
                    origin_ip = parts[1]
                    origin_port = int(parts[2])
                    filename = " ".join(parts[3:-1]).strip('"')
                    hops = int(parts[-1])
                    self.stats['recv'] += 1

                    if filename in self.files:
                        # Found locally
                        reply = format_message(f'SEROK 1 {self.ip} {self.chord_port} {hops + 1} {filename}')
                        self.sock.sendto(pack_msg(reply), (origin_ip, origin_port))
                        self.stats['ans'] += 1
                        print(f"[Search] Found '{filename}' locally. Responded to {origin_ip}:{origin_port}")
                    else:
                        # Not found: forward to successor
                        if hops < 10:  # max hops (TTL) safeguard
                            fwd_msg = format_message(f'SER {origin_ip} {origin_port} "{filename}" {hops + 1}')
                            self.sock.sendto(pack_msg(fwd_msg), (self.successor[1], self.successor[2]))
                            self.stats['fwd'] += 1
                            print(f"[Search] Forwarded '{filename}' to {self.successor}")
                        else:
                            # If hops exceed limit, send SEROK with 0 files
                            reply = format_message(f'SEROK 0 {self.ip} {self.chord_port} {hops + 1}')
                            self.sock.sendto(pack_msg(reply), (origin_ip, origin_port))
                            print(f"[Search] File '{filename}' not found within hop limit. Responded with 0 files.")


                elif cmd == 'SEROK' and len(parts) >= 5:
                    num_files = int(parts[1])
                    src_ip = parts[2]
                    src_port = int(parts[3])
                    hops = int(parts[4])
                    
                    if num_files > 0:
                        filenames = [f.strip('"') for f in parts[5:]]
                        print(f"[Search Result] Files found at {src_ip}:{src_port} in {hops} hops: {', '.join(filenames)}")
                    else:
                        print(f"[Search Result] No files found for the request originating from {src_ip}:{src_port} in {hops} hops.")


                else:
                    print(f"[udp_listener] Unknown command: {cmd}")
                    # Send generic ERROR for unknown commands
                    error_reply = format_message("ERROR")
                    self.sock.sendto(pack_msg(error_reply), addr)

            except Exception as e:
                print(f"[udp_listener] Error: {e}")


    def handle_find_ok(self, node_id, ip, port):
        try:
            print(f"[HandleFindOK] Received successor: ID={node_id}, IP={ip}, Port={port}")
            if self.successor[0] == self.id:
                self.successor = (node_id, ip, port)
        except Exception as e:
            print(f"[HandleFindOK] Error: {e}")

    def notify(self, potential_pred):
        pred_id, pred_ip, pred_port = potential_pred
        if (self.predecessor is None or
            in_interval(pred_id, self.predecessor[0], self.id)):
            self.predecessor = potential_pred
            print(f"[notify] Predecessor updated to: {self.predecessor}")

    def add_to_finger(self, nid, ip, port):
        for i in range(M):
            start = (self.id + 2 ** i) % MAX_ID
            # check if nid is between self.id and finger[i][0] inclusive right
            if in_interval(nid, self.id, self.finger[i][0] if self.finger[i] else self.id, inclusive_right=True):
                self.finger[i] = (nid, ip, port)

    def stabilize_loop(self):
        while self.running:
            time.sleep(STABILIZE_INTERVAL)
            try:
                succ_id, succ_ip, succ_port = self.successor
                succ_pred = self.send_get_predecessor(succ_ip, succ_port)

                if succ_pred and in_interval(succ_pred[0], self.id, succ_id):
                    self.successor = succ_pred

                self.send_notify(self.successor[1], self.successor[2], self.id, self.ip, self.chord_port)

            except Exception as e:
                print(f"[Stabilize] Error contacting successor {self.successor}: {e}")
                print(f"[Stabilize] Trying to find next alive successor from finger table...")

                # Try to find next live successor from finger table
                updated = False
                # Use a copy of finger to avoid issues if it's modified during iteration
                for finger in list(self.finger):
                    fid, fip, fport = finger
                    if fid == self.id:
                        continue  # Skip self

                    try:
                        if self.ping(fip, fport):  # You need to implement `ping`
                            self.successor = (fid, fip, fport)
                            print(f"[Stabilize] Updated successor to: {self.successor}")
                            updated = True
                            break
                    except Exception:
                        continue

                if not updated:
                    print("[Stabilize] No alive successor found. Ring might be broken.")


    def ping(self, ip, port, timeout=2):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            # Updated: Include message length for PING
            sock.sendto(pack_msg(format_message("PING")), (ip, port))
            data, _ = sock.recvfrom(1024)
            return unpack_msg(data) == "PONG"
        except:
            return False

    def fix_loop(self):
        i = 0
        while self.running:
            time.sleep(FIX_FINGERS_INTERVAL)
            try:
                start = (self.id + 2 ** i) % MAX_ID
                successor = self.find_successor(start)
                if successor:
                    self.finger[i] = successor

                # Print finger table nicely
                print(f"\n[{self.username}] [{self.id}] Finger Table:")
                print(f"{'Index':<5} {'Start':<5} {'Node ID':<10} {'IP':<15} {'Port'}")
                for idx in range(FINGER_SIZE):
                    start_val = (self.id + 2 ** idx) % MAX_ID
                    fid, ip, port = self.finger[idx]
                    print(f"{idx:<5} {start_val:<5} {fid:<10} {ip:<15} {port}")

                i = (i + 1) % FINGER_SIZE
            except Exception as e:
                print(f"[FixFingers] Error fixing finger {i}: {e}")

    def is_node_alive(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            # Updated: Include message length for PING
            sock.sendto(pack_msg(format_message("PING")), (ip, port))
            data, _ = sock.recvfrom(1024)
            return unpack_msg(data) == "PONG"
        except:
            return False

    def find_successor(self, id):
        if self.successor and in_interval(id, self.id, self.successor[0], inclusive_right=True):
            return self.successor
        else:
            closest = self.closest_preceding_node(id)
            if closest == (self.id, self.ip, self.chord_port):
                return self.successor
            try:
                # Updated: Include message length for FIND
                msg = format_message(f"FIND {id} {self.ip} {self.chord_port}")
                self.sock.sendto(pack_msg(msg), (closest[1], closest[2]))

                data, _ = self.sock.recvfrom(UDP_BUFFER)
                msg_parts = unpack_msg(data).split()
                if msg_parts[0] == "FNDOK":
                    # FNDOK format: FNDOK <id> <ip> <port> -> parts[1], parts[2], parts[3]
                    return (int(msg_parts[1]), msg_parts[2], int(msg_parts[3]))
            except Exception as e:
                print(f"[find_successor] Error contacting node {closest}: {e}")
        return None

    def closest_preceding_node(self, id):
        for i in reversed(range(FINGER_SIZE)):
            finger = self.finger[i]
            if finger and in_interval(finger[0], self.id, id):
                return finger
        return (self.id, self.ip, self.chord_port)

    def check_predecessor_loop(self):
        while self.running:
            time.sleep(CHECK_PREDECESSOR_INTERVAL)
            # if self.predecessor and not self.is_node_alive(self.predecessor[1], self.predecessor[2]):
            #     print(f"Predecessor {self.predecessor} is not alive. Clearing predecessor.")
            #     self.predecessor = None

    def send_get_predecessor(self, ip, port):
        try:
            ip = str(ip)
            port = int(port)
            if not (0 <= port <= 65535):
                raise ValueError(f"Port out of valid range: {port}")

            # Updated: Include message length for GETPRED
            msg = format_message("GETPRED")
            self.sock.sendto(pack_msg(msg), (ip, port))
            data, _ = self.sock.recvfrom(UDP_BUFFER)
            msg_parts = unpack_msg(data).split()
            if msg_parts[0] == "RESPRED":
                # RESPRED format: RESPRED <id> <ip> <port> -> parts[1], parts[2], parts[3]
                return (int(msg_parts[1]), msg_parts[2], int(msg_parts[3]))
        except Exception as e:
            print(f"[send_get_predecessor] Error: {e}")
        return None

    def send_notify(self, ip, port, nid, my_ip, my_port):
        try:
            ip = str(ip)
            port = int(port)
            if not (0 <= port <= 65535):
                raise ValueError(f"Port out of valid range: {port}")

            # Updated: Include message length for NOTIFY
            msg = format_message(f"NOTIFY {nid} {my_ip} {my_port}")
            self.sock.sendto(pack_msg(msg), (ip, port))
        except Exception as e:
            print(f"[send_notify] Error: {e}")

    def search(self, filename):
        # Updated: Include message length for SER
        msg = format_message(f'SER {self.ip} {self.chord_port} "{filename}" 0')
        self.sock.sendto(pack_msg(msg), (self.successor[1], self.successor[2]))
        self.stats['sent'] += 1

    def leave(self):
        self.running = False
        print(f"[{self.username}] Leaving the ring...")

        # Notify successor and predecessor to reconnect to each other
        if self.predecessor and self.successor and self.successor != (self.id, self.ip, self.chord_port):
            # Notify predecessor to update its successor to my successor
            pred_id, pred_ip, pred_port = self.predecessor
            # Updated: Include message length for UPDATE_SUCCESSOR
            msg = format_message(f"UPDATE_SUCCESSOR {self.successor[0]} {self.successor[1]} {self.successor[2]}")
            self.sock.sendto(pack_msg(msg), (pred_ip, pred_port))

            # Notify successor to update its predecessor to my predecessor
            succ_id, succ_ip, succ_port = self.successor
            # Updated: Include message length for UPDATE_PREDECESSOR
            msg = format_message(f"UPDATE_PREDECESSOR {pred_id} {pred_ip} {pred_port}")
            self.sock.sendto(pack_msg(msg), (succ_ip, succ_port))

        # Unregister from bootstrap
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            # REG message format for BS remains unchanged (not part of Chord protocol)
            sock.sendto(pack_msg(f"UNREG {self.ip} {self.chord_port} {self.username}"), (BS_IP, BS_PORT))
            try:
                data, _ = sock.recvfrom(1024)
                response = unpack_msg(data)
                print(f"[Leave] Bootstrap response: {response}")
            except socket.timeout:
                print("[Leave] No response from bootstrap server (UNREG)")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 5:
        print("Usage: chord_node.py <ip> <chord_port> <rest_port> <username>")
    else:
        try:
            n = ChordNode(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
            n.start()
            while True:
                cmd = input("> ")
                if cmd.startswith("search"):
                    _, f = cmd.split(maxsplit=1)
                    n.search(f)
                elif cmd == "files":
                    print(n.files)
                elif cmd == "leave":
                    n.leave()
                    break
                elif cmd == "stats":
                    print(f"[{n.username}] Stats: Sent: {n.stats['sent']}, Received: {n.stats['recv']}, Forwarded: {n.stats['fwd']}, Answered: {n.stats['ans']}")
                else:
                    print("Unknown command. Available commands: search <filename>, files, leave, stats")
        except KeyboardInterrupt:
            print("\nKeyboardInterrupt detected. Attempting to leave the Chord network...")
            if 'n' in locals() and isinstance(n, ChordNode): # Ensure 'n' exists and is a ChordNode instance
                n.leave()
            sys.exit(0) # Exit cleanly after handling the interrupt
        except Exception as e:
            print(f"Error in ChordNode: {e}")
            if 'n' in locals() and isinstance(n, ChordNode): # Ensure 'n' exists and is a ChordNode instance
                n.leave()
            sys.exit(1)
