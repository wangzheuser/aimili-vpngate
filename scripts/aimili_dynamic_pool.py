#!/usr/bin/env python3
"""SOCKS5 dynamic pool for AimiliVPN exit slots.

The pool is intentionally independent from x-ui. x-ui only needs one SOCKS5
outbound pointing at this listener; slot membership is reconciled in memory.
"""

from __future__ import annotations

import argparse
import dataclasses
import ipaddress
import json
import logging
import os
import select
import signal
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable


LOG = logging.getLogger("aimili-dynamic-pool")
SOCKS_VERSION = 5
NO_AUTH = 0
USERPASS_AUTH = 2
SOCKS_REPLY_SUCCEEDED = 0


@dataclasses.dataclass
class Slot:
    index: int
    host: str
    port: int
    exit_ip: str = ""
    in_flight: int = 0
    last_error: str = ""
    username: str = ""
    password: str = ""


def _valid_listen_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _slot_from_json(item: Any) -> Slot | None:
    if not isinstance(item, dict):
        return None
    if item.get("status") != "up" or item.get("egress_ok") is not True:
        return None
    try:
        index = int(item["slot"])
        port = int(item["port"])
    except (KeyError, TypeError, ValueError):
        return None
    if not 1 <= port <= 65535:
        return None
    return Slot(
        index=index,
        host="127.0.0.1",
        port=port,
        exit_ip=str(item.get("exit_ip") or ""),
        username=str(item.get("proxy_username") or ""),
        password=str(item.get("proxy_password") or ""),
    )


def active_slots(payload: Any) -> list[Slot]:
    """Return only healthy slots advertised by AimiliVPN."""

    if isinstance(payload, dict):
        payload = payload.get("slots", [])
    if not isinstance(payload, list):
        return []
    result = [_slot_from_json(item) for item in payload]
    return sorted((slot for slot in result if slot is not None), key=lambda x: x.index)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("peer closed before SOCKS5 frame completed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _encode_address(host: str, port: int) -> bytes:
    try:
        packed = socket.inet_aton(host)
    except OSError:
        packed = None
    if packed is not None:
        return bytes([1]) + packed + port.to_bytes(2, "big")
    try:
        packed6 = socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        packed6 = None
    if packed6 is not None:
        return bytes([4]) + packed6 + port.to_bytes(2, "big")
    encoded = host.encode("idna")
    if len(encoded) > 255:
        raise ValueError("SOCKS5 domain name is too long")
    return bytes([3, len(encoded)]) + encoded + port.to_bytes(2, "big")


def _read_address(sock: socket.socket) -> tuple[str, int]:
    atyp = _recv_exact(sock, 1)[0]
    return _read_address_body(sock, atyp)


def _read_address_body(sock: socket.socket, atyp: int) -> tuple[str, int]:
    if atyp == 1:
        host = socket.inet_ntoa(_recv_exact(sock, 4))
    elif atyp == 3:
        length = _recv_exact(sock, 1)[0]
        host = _recv_exact(sock, length).decode("idna")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, _recv_exact(sock, 16))
    else:
        raise ValueError(f"unsupported SOCKS5 address type: {atyp}")
    port = int.from_bytes(_recv_exact(sock, 2), "big")
    return host, port


def _socks5_connect(
    sock: socket.socket,
    host: str,
    port: int,
    credentials: tuple[str, str] | None = None,
) -> None:
    if credentials and credentials[0] and credentials[1]:
        sock.sendall(bytes([SOCKS_VERSION, 1, USERPASS_AUTH]))
        response = _recv_exact(sock, 2)
        if response != bytes([SOCKS_VERSION, USERPASS_AUTH]):
            raise ConnectionError("upstream SOCKS5 server rejected username/password mode")
        username, password = (value.encode("utf-8") for value in credentials)
        if len(username) > 255 or len(password) > 255:
            raise ValueError("SOCKS5 credentials are too long")
        sock.sendall(bytes([1, len(username)]) + username + bytes([len(password)]) + password)
        auth_response = _recv_exact(sock, 2)
        if auth_response != b"\x01\x00":
            raise ConnectionError("upstream SOCKS5 authentication failed")
    else:
        sock.sendall(bytes([SOCKS_VERSION, 1, NO_AUTH]))
        response = _recv_exact(sock, 2)
        if response != bytes([SOCKS_VERSION, NO_AUTH]):
            raise ConnectionError("upstream SOCKS5 server rejected no-auth mode")
    sock.sendall(bytes([SOCKS_VERSION, 1, 0]) + _encode_address(host, port))
    response = _recv_exact(sock, 4)
    if response[0] != SOCKS_VERSION or response[1] != SOCKS_REPLY_SUCCEEDED:
        raise ConnectionError(f"upstream SOCKS5 CONNECT failed: reply={response[1]}")
    _read_address_body(sock, response[3])


def _failure_reply(code: int) -> bytes:
    return bytes([SOCKS_VERSION, code, 0, 1]) + b"\x00\x00\x00\x00\x00\x00"


class SlotPool:
    def __init__(self, config: dict[str, Any]):
        self._state_file = str(config.get("state_file") or "")
        raw_command = config.get("state_command")
        self._state_command = [str(value) for value in raw_command] if isinstance(raw_command, list) else []
        self._poll_interval = max(5.0, float(config.get("poll_interval", 15)))
        self._auth_refresh_interval = max(1.0, float(config.get("auth_refresh_interval", 2)))
        self._health_timeout = max(1.0, float(config.get("health_timeout", 8)))
        self._probe_host = str(config.get("probe_host", "api.ipify.org"))
        self._probe_port = int(config.get("probe_port", 80))
        self._slots: dict[int, Slot] = {}
        self._credentials: tuple[str, str] | None = None
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._refresh_now = threading.Event()
        self._round_robin = 0

    @property
    def poll_interval(self) -> float:
        return self._poll_interval

    def stop(self) -> None:
        self._stop.set()
        self._refresh_now.set()

    def _read_state(self) -> Any:
        if self._state_file:
            return json.loads(Path(self._state_file).read_text(encoding="utf-8"))
        if not self._state_command:
            raise RuntimeError("state_file or state_command is required")
        completed = subprocess.run(
            self._state_command,
            check=True,
            capture_output=True,
            text=True,
            timeout=max(5.0, self._health_timeout),
        )
        return json.loads(completed.stdout)

    def _probe(self, slot: Slot) -> tuple[Slot, bool, str]:
        try:
            with socket.create_connection((slot.host, slot.port), timeout=self._health_timeout) as upstream:
                upstream.settimeout(self._health_timeout)
                _socks5_connect(upstream, self._probe_host, self._probe_port, (slot.username, slot.password))
            return slot, True, ""
        except Exception as exc:  # pragma: no cover - exact socket errors vary by platform
            return slot, False, f"{type(exc).__name__}: {exc}"

    def refresh(self) -> None:
        try:
            state = self._read_state()
            candidates = active_slots(state)
            self._set_credentials_from_state(state)
        except Exception as exc:
            LOG.warning("读取 Aimili 槽位失败: %s", exc)
            return

        checked: list[Slot] = []
        if candidates:
            with ThreadPoolExecutor(max_workers=min(8, len(candidates))) as executor:
                for slot, ok, error in executor.map(self._probe, candidates):
                    if ok:
                        checked.append(slot)
                    else:
                        LOG.warning("槽位 %s 健康检查失败: %s", slot.index, error)

        with self._lock:
            before = set(self._slots)
            self._slots = {slot.index: slot for slot in checked}
            after = set(self._slots)
        if before != after:
            LOG.info("动态出口池更新: active=%s", sorted(after))

    def _set_credentials_from_state(self, state: Any) -> None:
        pool_auth = state.get("dynamic_pool_auth") if isinstance(state, dict) else None
        credentials = None
        if isinstance(pool_auth, dict) and pool_auth.get("username") and pool_auth.get("password"):
            credentials = (str(pool_auth["username"]), str(pool_auth["password"]))
        with self._lock:
            self._credentials = credentials

    def refresh_credentials(self) -> None:
        try:
            self._set_credentials_from_state(self._read_state())
        except Exception as exc:
            LOG.warning("读取动态池认证配置失败: %s", exc)

    def choose(self) -> Slot | None:
        with self._lock:
            if not self._slots:
                return None
            slots = sorted(self._slots.values(), key=lambda item: (item.in_flight, item.index))
            index = self._round_robin % len(slots)
            self._round_robin += 1
            slot = slots[index]
            slot.in_flight += 1
            return slot

    def release(self, slot: Slot) -> None:
        with self._lock:
            current = self._slots.get(slot.index)
            if current is not None and current.in_flight:
                current.in_flight -= 1

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dataclasses.asdict(slot) for slot in sorted(self._slots.values(), key=lambda x: x.index)]

    def credentials(self) -> tuple[str, str] | None:
        with self._lock:
            return self._credentials

    def run(self) -> None:
        next_refresh = 0.0
        next_auth_refresh = 0.0
        while not self._stop.is_set():
            now = time.monotonic()
            if now >= next_refresh:
                self.refresh()
                next_refresh = now + self._poll_interval
            if now >= next_auth_refresh:
                self.refresh_credentials()
                next_auth_refresh = now + self._auth_refresh_interval
            self._refresh_now.wait(timeout=max(0.2, min(next_refresh, next_auth_refresh) - time.monotonic()))
            self._refresh_now.clear()


class SocksPoolServer:
    def __init__(self, host: str, port: int, pool: SlotPool, backlog: int = 128):
        self.host = host
        self.port = port
        self.pool = pool
        self.backlog = backlog
        self._stop = threading.Event()
        self._listener: socket.socket | None = None

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass

    def serve_forever(self) -> None:
        listener = socket.socket(socket.AF_INET6 if ":" in self.host else socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.port))
        listener.listen(self.backlog)
        listener.settimeout(1.0)
        self._listener = listener
        LOG.info("SOCKS5 动态池监听 %s:%s", self.host, self.port)
        while not self._stop.is_set():
            try:
                client, address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(client, address), daemon=True).start()

    def _handle_client(self, client: socket.socket, address: Any) -> None:
        client.settimeout(20)
        slot: Slot | None = None
        upstream: socket.socket | None = None
        try:
            header = _recv_exact(client, 2)
            if header[0] != SOCKS_VERSION:
                return
            methods = _recv_exact(client, header[1])
            credentials = self.pool.credentials()
            if credentials is not None:
                if USERPASS_AUTH not in methods:
                    client.sendall(bytes([SOCKS_VERSION, 0xFF]))
                    return
                client.sendall(bytes([SOCKS_VERSION, USERPASS_AUTH]))
                auth_header = _recv_exact(client, 2)
                if auth_header[0] != 1:
                    client.sendall(b"\x01\x01")
                    return
                username = _recv_exact(client, auth_header[1]).decode("utf-8", errors="replace")
                password_length = _recv_exact(client, 1)[0]
                password = _recv_exact(client, password_length).decode("utf-8", errors="replace")
                if (username, password) != credentials:
                    client.sendall(b"\x01\x01")
                    return
                client.sendall(b"\x01\x00")
            elif NO_AUTH not in methods:
                client.sendall(bytes([SOCKS_VERSION, 0xFF]))
                return
            else:
                client.sendall(bytes([SOCKS_VERSION, NO_AUTH]))

            request = _recv_exact(client, 4)
            if request[0] != SOCKS_VERSION or request[1] != 1:
                client.sendall(_failure_reply(7))
                return
            target_host, target_port = _read_address_body(client, request[3])

            for _ in range(2):
                slot = self.pool.choose()
                if slot is None:
                    break
                try:
                    upstream = socket.create_connection((slot.host, slot.port), timeout=20)
                    upstream.settimeout(20)
                    _socks5_connect(upstream, target_host, target_port, (slot.username, slot.password))
                    break
                except Exception as exc:
                    LOG.warning("槽位 %s 建立连接失败: %s", slot.index, exc)
                    self.pool.release(slot)
                    slot = None
                    if upstream is not None:
                        upstream.close()
                        upstream = None
            if slot is None or upstream is None:
                client.sendall(_failure_reply(4))
                return

            client.sendall(bytes([SOCKS_VERSION, 0, 0, 1]) + b"\x00\x00\x00\x00\x00\x00")
            self._relay(client, upstream)
        except (ConnectionError, OSError, ValueError) as exc:
            LOG.warning("SOCKS5 client %s failed: %s", address, exc)
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            try:
                client.close()
            except OSError:
                pass
            if slot is not None:
                self.pool.release(slot)

    @staticmethod
    def _relay(left: socket.socket, right: socket.socket) -> None:
        left.settimeout(None)
        right.settimeout(None)
        sockets = [left, right]
        while sockets:
            readable, _, exceptional = select.select(sockets, [], sockets, 60)
            if exceptional:
                return
            if not readable:
                continue
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                destination = right if source is left else left
                destination.sendall(data)


def load_config(path: str) -> dict[str, Any]:
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    host = str(config.get("listen_host", "127.0.0.1"))
    if not _valid_listen_host(host):
        raise ValueError("listen_host must be localhost or a valid IP address")
    port = int(config.get("listen_port", 17928))
    if not 1024 <= port <= 65535:
        raise ValueError("listen_port must be between 1024 and 65535")
    if not config.get("state_file") and not config.get("state_command"):
        raise ValueError("state_file or state_command is required")
    config["listen_host"] = host
    config["listen_port"] = port
    return config


def main() -> int:
    parser = argparse.ArgumentParser(description="AimiliVPN dynamic SOCKS5 pool")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = load_config(args.config)
    pool = SlotPool(config)
    server = SocksPoolServer(config["listen_host"], config["listen_port"], pool)

    def shutdown(_signum: int, _frame: Any) -> None:
        pool.stop()
        server.stop()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    pool.refresh()
    controller = threading.Thread(target=pool.run, name="slot-reconciler", daemon=True)
    controller.start()
    try:
        server.serve_forever()
    finally:
        shutdown(signal.SIGTERM, None)
        controller.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
