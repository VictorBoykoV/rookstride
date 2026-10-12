"""Small local-only VICI client. Wire format follows strongSwan's VICI README."""
import socket
import struct
from collections import deque

MAX_PACKET = 512 * 1024


def encode(values):
    out = bytearray()
    for key, value in values.items():
        name = key.encode()
        if not 0 < len(name) <= 255:
            raise ValueError("Invalid VICI name")
        if isinstance(value, dict):
            out += b"\x01" + bytes([len(name)]) + name + encode(value) + b"\x02"
        elif isinstance(value, list):
            out += b"\x04" + bytes([len(name)]) + name
            for item in value:
                data = str(item).encode()
                out += b"\x05" + struct.pack("!H", len(data)) + data
            out += b"\x06"
        else:
            data = str(value).encode()
            out += b"\x03" + bytes([len(name)]) + name + struct.pack("!H", len(data)) + data
    return bytes(out)


def decode(data):
    pos = 0
    stack = [{}]
    current_list = None

    def take(count):
        nonlocal pos
        if pos + count > len(data):
            raise ValueError("Truncated VICI message")
        value = data[pos:pos + count]
        pos += count
        return value

    while pos < len(data):
        kind = take(1)[0]
        if kind in (1, 3, 4):
            name = take(take(1)[0]).decode()
        if kind == 1:
            child = {}
            stack[-1][name] = child
            stack.append(child)
        elif kind == 2:
            if len(stack) == 1:
                raise ValueError("Unbalanced VICI section")
            stack.pop()
        elif kind == 3:
            value = take(struct.unpack("!H", take(2))[0]).decode(errors="replace")
            stack[-1][name] = value
        elif kind == 4:
            if current_list is not None:
                raise ValueError("Nested VICI list")
            current_list = []
            stack[-1][name] = current_list
        elif kind == 5:
            if current_list is None:
                raise ValueError("Missing VICI list")
            current_list.append(take(struct.unpack("!H", take(2))[0]).decode(errors="replace"))
        elif kind == 6:
            if current_list is None:
                raise ValueError("Unexpected VICI list end")
            current_list = None
        else:
            raise ValueError("Unknown VICI element")
    if len(stack) != 1 or current_list is not None:
        raise ValueError("Unclosed VICI element")
    return stack[0]


class Vici:
    def __init__(self, path="/var/run/charon.vici", timeout=5):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(path)
        self.pending = deque()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.sock.close()

    def send(self, kind, name="", values=None):
        payload = bytes([kind])
        if kind in (0, 3, 4):
            n = name.encode()
            payload += bytes([len(n)]) + n
        payload += encode(values or {})
        self.sock.sendall(struct.pack("!I", len(payload)) + payload)

    def receive(self):
        if self.pending:
            return self.pending.popleft()
        return self._receive()

    def _receive(self):
        def read(count):
            out = bytearray()
            while len(out) < count:
                part = self.sock.recv(count - len(out))
                if not part:
                    raise ConnectionError("VICI connection closed")
                out += part
            return bytes(out)
        size = struct.unpack("!I", read(4))[0]
        if not 1 <= size <= MAX_PACKET:
            raise ValueError("Invalid VICI packet size")
        body = read(size)
        kind, name, offset = body[0], "", 1
        if kind == 7:
            if len(body) < 2 or len(body) < 2 + body[1]:
                raise ValueError("Truncated VICI event")
            name = body[2:2 + body[1]].decode()
            offset = 2 + body[1]
        return kind, name, decode(body[offset:])

    def register(self, name):
        self.send(3, name)
        while True:
            packet = self._receive()
            if packet[0] == 7:
                self.pending.append(packet)
            elif packet[0] == 5:
                return
            else:
                raise RuntimeError("VICI event registration failed")

    def request(self, name, values=None, event=None):
        if event:
            self.register(event)
        self.send(0, name, values)
        streamed = []
        while True:
            kind, event_name, message = self._receive()
            if kind == 7:
                if event_name == event:
                    streamed.append(message)
                else:
                    self.pending.append((kind, event_name, message))
            elif kind == 1:
                if message.get("success") == "no":
                    raise RuntimeError(message.get("errmsg", "VICI request failed"))
                return streamed if event else message
            else:
                raise RuntimeError("Unexpected VICI response")


def sessions():
    with Vici() as client:
        return client.request("list-sas", event="list-sa")


def connections(messages, include_deleted=False):
    result = []
    for message in messages:
        for name, ike in message.items():
            if not isinstance(ike, dict):
                continue
            user = ike.get("remote-eap-id") or ike.get("remote-id", "unknown")
            children = []
            for child in ike.get("child-sas", {}).values():
                if not isinstance(child, dict) or (not include_deleted and child.get("state") not in ("INSTALLED", "REKEYING", "DELETING")):
                    continue
                children.append({"id": str(child.get("uniqueid", "")),
                                 "upload": int(child.get("bytes-in", 0)),
                                 "download": int(child.get("bytes-out", 0))})
            result.append({"id": str(ike.get("uniqueid", "")), "user": user,
                           "state": ike.get("state", "UNKNOWN"),
                           "endpoint": ike.get("remote-host", ""),
                           "port": int(ike.get("remote-port", 0)),
                           "client_identity": ike.get("remote-id", ""),
                           "vpn_addresses": ike.get("remote-vips", []),
                           "age": int(ike.get("established", 0)), "children": children,
                           "upload": sum(x["upload"] for x in children),
                           "download": sum(x["download"] for x in children)})
    return result
