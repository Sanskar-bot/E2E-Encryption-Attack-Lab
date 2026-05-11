"""
server.py
Role: Relay server — waits for at least two clients before relaying.
      Any messages sent before the second client connects are buffered
      and flushed to all peers the moment the lobby is "open" (≥ 2 clients).
      Never reads or modifies message content.
Usage: python server.py
       Listens on 127.0.0.1:9000
"""

import socket
import threading
import time

HOST = "127.0.0.1"
PORT = 9000

# ── Shared state ──────────────────────────────────────────────────────────────
clients: list[socket.socket] = []       # all currently-connected sockets
clients_lock = threading.Lock()

# Messages buffered while only one client is connected
pending_queue: list[tuple[bytes, socket.socket]] = []   # (raw_bytes, sender)
pending_lock  = threading.Lock()

# Set to True once 2+ clients have connected.
# Resets to False when all clients disconnect so the next session starts fresh.
lobby_open   = False
lobby_event  = threading.Event()        # signalled when lobby_open becomes True

# Captured log for the dashboard (last 200 entries)
captured_log: list[dict] = []
log_lock = threading.Lock()


# ── Helpers ───────────────────────────────────────────────────────────────────

def log_event(raw: bytes) -> None:
    """Append a raw packet to the captured_log with a timestamp."""
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "raw":  raw[:200].decode(errors="replace"),
    }
    with log_lock:
        captured_log.append(entry)
        if len(captured_log) > 200:
            captured_log.pop(0)


def broadcast(data: bytes, sender_sock: socket.socket) -> None:
    """Forward raw data to every connected client except the sender."""
    with clients_lock:
        targets = [s for s in clients if s is not sender_sock]
    for sock in targets:
        try:
            sock.sendall(data)
        except Exception:
            with clients_lock:
                if sock in clients:
                    clients.remove(sock)


def flush_pending() -> None:
    """Relay all buffered messages now that a second client is present."""
    with pending_lock:
        queue = list(pending_queue)
        pending_queue.clear()

    if queue:
        print(f"[server] Flushing {len(queue)} buffered message(s) to all peers.")

    for raw, sender in queue:
        log_event(raw)
        print(f"[server] flush ({len(raw)} bytes): {raw[:80].decode(errors='replace')}")
        broadcast(raw, sender)


# ── Per-client thread ─────────────────────────────────────────────────────────

def handle_client(conn: socket.socket, addr: tuple) -> None:
    """Receive data from one client; queue or relay depending on lobby state."""
    global lobby_open   # declared at top so Python sees it before any read/write

    print(f"[server] Connected: {addr}")

    with clients_lock:
        clients.append(conn)
        n = len(clients)

    # If this is the second (or later) client, open the lobby and flush queue
    if n >= 2 and not lobby_open:
        lobby_open = True
        lobby_event.set()
        print(f"[server] Lobby open — {n} clients connected. Starting relay.")
        flush_pending()
    elif lobby_open:
        # A late-joining third client: just confirm relay is already live
        print(f"[server] New client #{n} joined an already-open lobby.")
    else:
        print(f"[server] Waiting for a second client before relaying…")

    try:
        buf = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk

            # Messages are newline-delimited JSON
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                raw = line + b"\n"

                if lobby_open:
                    # Relay immediately
                    log_event(raw)
                    print(f"[server] relay ({len(raw)} bytes): {raw[:80].decode(errors='replace')}")
                    broadcast(raw, conn)
                else:
                    # Buffer until a second peer arrives
                    print(f"[server] buffered ({len(raw)} bytes) — waiting for peer.")
                    with pending_lock:
                        pending_queue.append((raw, conn))

    except Exception as e:
        print(f"[server] Error from {addr}: {e}")
    finally:
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
            remaining = len(clients)
        conn.close()
        print(f"[server] Disconnected: {addr}")

        # ── Reset lobby when the session is fully over ────────────────────────
        # If no clients remain, the current session has ended. Reset all shared
        # state so the next Alice+Bob pair starts from a clean lobby instead of
        # inheriting lobby_open=True and having their messages relay into the void.
        if remaining == 0:
            lobby_open = False
            lobby_event.clear()
            with pending_lock:
                pending_queue.clear()
            print("[server] All clients disconnected — lobby reset for next session.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(10)
    print(f"[server] Relay server listening on {HOST}:{PORT}")
    print("[server] Will buffer messages until at least 2 clients are connected.")
    print("[server] Waiting for connections… (Ctrl-C to stop)")
    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[server] Shutting down.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
