#!/usr/bin/env python3
"""SUBSCRIBE packets that omit the final options byte must be rejected.

The broker image is taken from ../build/Dockerfile. These checks fail while
that broker still accepts the packet or records the topic. A fixed broker
rejects the packet, records nothing, and stays up.

Run:
  python3 devenv/docker/blocks/mqtt/subscribe_bounds_test/test_malformed_subscribe.py
"""

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[1] / "build" / "Dockerfile"
HERE = Path(__file__).resolve().parent
NANOMQ_REPO = "https://github.com/nanomq/nanomq.git"
NANONNG_REPO = "https://github.com/nanomq/NanoNNG.git"

# Obvious placeholder. The broker under test requires a username and password.
USER = "placeholder"
PASSWORD = "placeholder"

MODES = [
    "subinfo-v5-valid",
    "subinfo-v5-missing",
    "subinfo-v311-missing",
    "subinfo-v5-exact",
    "subinfo-v311-exact",
    "decode-v5-valid",
    "decode-v5-missing",
    "decode-v311-missing",
    "decode-v5-exact",
]


def image_version():
    for line in DOCKERFILE.read_text().splitlines():
        line = line.strip()
        if line.startswith("FROM "):
            image = line.split()[1]
            tag = image.rsplit(":", 1)[-1]
            if tag.endswith("-full"):
                tag = tag[: -len("-full")]
            return tag
    raise SystemExit(f"no FROM image in {DOCKERFILE}")


def run(cmd, **kwargs):
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, **kwargs)


def ensure_broker(version):
    bin_override = os.environ.get("NANOMQ_BIN")
    lib_override = os.environ.get("NANOMQ_LIB")
    src_override = os.environ.get("NANOMQ_SRC")
    if bin_override and lib_override and src_override:
        return Path(bin_override), Path(lib_override), Path(src_override)

    cache = Path(tempfile.gettempdir()) / f"nanomq-bounds-{version}"
    src = cache / "src"
    if not (src / "CMakeLists.txt").exists():
        if src.exists():
            subprocess.run(["rm", "-rf", str(src)], check=True)
        run(["git", "clone", "--depth", "1", "--branch", version, NANOMQ_REPO, str(src)])
    nng_commit = subprocess.check_output(
        ["git", "-C", str(src), "rev-parse", f"HEAD:nng"], text=True
    ).strip()
    nng = src / "nng"
    if not (nng / "CMakeLists.txt").exists():
        if nng.exists():
            subprocess.run(["rm", "-rf", str(nng)], check=True)
        run(["git", "clone", NANONNG_REPO, str(nng)])
        run(["git", "-C", str(nng), "checkout", nng_commit])
    build = cache / "build"
    binary = build / "nanomq" / "nanomq"
    library = build / "nng" / "libnng.a"
    if not binary.exists() or not library.exists():
        run(
            [
                "cmake",
                "-S",
                str(src),
                "-B",
                str(build),
                "-DCMAKE_BUILD_TYPE=Debug",
                "-DCMAKE_C_COMPILER=gcc",
                "-DCMAKE_CXX_COMPILER=g++",
                "-DBUILD_NANOMQ_CLI=OFF",
                "-DBUILD_CLIENT=OFF",
                "-DBUILD_NNG_PROXY=OFF",
                "-DBUILD_BENCH=OFF",
                "-DNNG_TESTS=OFF",
                "-DNNG_ENABLE_TLS=OFF",
                "-DENABLE_ACL=ON",
                "-DCMAKE_C_FLAGS=-fsanitize=address -fno-omit-frame-pointer -g -O1",
                "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address",
            ]
        )
        run(["cmake", "--build", str(build), "-j4", "--target", "nanomq"])
    return binary, library, src


def compile_unit(library, src):
    out = Path(tempfile.gettempdir()) / "decode_bounds_test"
    sub_handler = (
        library.parent.parent
        / "nanomq"
        / "CMakeFiles"
        / "nanomq.dir"
        / "sub_handler.c.o"
    )
    cmd = [
        "gcc",
        "-fsanitize=address",
        "-fno-omit-frame-pointer",
        "-g",
        "-O1",
        "-std=gnu99",
        "-DNNG_STATIC_LIB",
        "-DACL_SUPP",
        f"-I{src / 'nanomq'}",
        f"-I{src / 'nanomq' / 'include'}",
        f"-I{src / 'nng' / 'include'}",
        f"-I{src / 'nng' / 'src'}",
        "-Wl,--unresolved-symbols=ignore-all",
        "-o",
        str(out),
        str(HERE / "decode_bounds_test.c"),
        str(sub_handler),
        str(library),
        "-pthread",
        "-latomic",
        "-lm",
    ]
    run(cmd)
    return out


def encode_remaining(length):
    out = bytearray()
    while True:
        digit = length % 128
        length //= 128
        if length:
            digit |= 0x80
        out.append(digit)
        if not length:
            return bytes(out)


def mqtt_str(text):
    raw = text.encode()
    return len(raw).to_bytes(2, "big") + raw


def connect_packet(client_id, version, username=None, password=None):
    flags = 0x02
    payload = mqtt_str(client_id)
    if username is not None:
        flags |= 0x80 | 0x40
        payload += mqtt_str(username) + mqtt_str(password)
    if version == 5:
        variable = mqtt_str("MQTT") + bytes([5, flags, 0x00, 0x3C, 0x00]) + payload
    else:
        variable = mqtt_str("MQTT") + bytes([4, flags, 0x00, 0x3C]) + payload
    return bytes([0x10]) + encode_remaining(len(variable)) + variable


def subscribe_packet(version, packet_id, topic, with_options):
    body = bytearray(packet_id.to_bytes(2, "big"))
    if version == 5:
        body.append(0x00)
    body += mqtt_str(topic)
    if with_options:
        body.append(0x00)
    return bytes([0x82]) + encode_remaining(len(body)) + bytes(body)


def publish_packet(version, topic, payload):
    body = bytearray(mqtt_str(topic))
    if version == 5:
        body.append(0x00)
    body += payload
    return bytes([0x30]) + encode_remaining(len(body)) + bytes(body)


def recvn(sock, count):
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def read_packet(sock):
    first = recvn(sock, 1)
    remaining = 0
    shift = 0
    while True:
        digit = recvn(sock, 1)[0]
        remaining += (digit & 0x7F) << shift
        if not digit & 0x80:
            break
        shift += 7
    body = recvn(sock, remaining) if remaining else b""
    return first[0], body


def reason_of_connack(body):
    if len(body) < 2:
        return 0xFF
    return body[1]


def suback_granted(body):
    """True when any reason code in the SUBACK grants the subscription."""
    if len(body) < 3:
        return False
    # MQTT v5: packet id, property length, reason codes.
    # MQTT v3.1.1: packet id, reason codes. Property length 0 is one zero byte,
    # so skipping a single zero after the packet id works for both of these tests.
    rest = body[2:]
    if rest and rest[0] == 0:
        rest = rest[1:]
    return any(code < 0x80 for code in rest)


class Broker:
    def __init__(self, binary, port):
        self.binary = binary
        self.port = port
        self.proc = None
        self.root = None

    def start(self):
        self.root = tempfile.TemporaryDirectory()
        base = Path(self.root.name)
        pwd = base / "pwd.conf"
        acl = base / "acl.conf"
        conf = base / "nanomq.conf"
        pwd.write_text(f"{USER}:{PASSWORD}\n")
        acl.write_text(
            "rules = [\n"
            f'  {{"permit": "allow", "username": "{USER}", "action": "subscribe", "topics": ["#"]}}\n'
            f'  {{"permit": "allow", "username": "{USER}", "action": "publish", "topics": ["#"]}}\n'
            '  {"permit": "deny"}\n'
            "]\n"
        )
        conf.write_text(
            "\n".join(
                [
                    "listeners.tcp {",
                    f'  bind = "127.0.0.1:{self.port}"',
                    "}",
                    "auth {",
                    "  allow_anonymous = false",
                    "  no_match = deny",
                    "  deny_action = disconnect",
                    f'  password = {{include "{pwd}"}}',
                    "  acl = {",
                    f'    include "{acl}"',
                    "  }",
                    "}",
                    "",
                ]
            )
        )
        os.makedirs("/tmp/nanomq", exist_ok=True)
        pid_path = Path("/tmp/nanomq/nanomq.pid")
        if pid_path.exists():
            pid_path.unlink()
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        self.proc = subprocess.Popen(
            [str(self.binary), "start", "--conf", str(conf)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        deadline = time.time() + 10
        last = None
        while time.time() < deadline:
            if self.proc.poll() is not None:
                err = self.proc.stderr.read().decode(errors="replace")
                raise RuntimeError(f"broker exited early: {err}")
            try:
                sock = socket.create_connection(("127.0.0.1", self.port), 0.2)
                sock.close()
                return
            except OSError as exc:
                last = exc
                time.sleep(0.05)
        raise RuntimeError(f"broker did not listen: {last}")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
        err = b""
        if self.proc and self.proc.stderr:
            err = self.proc.stderr.read()
        if self.root:
            self.root.cleanup()
        return err.decode(errors="replace")

    def alive(self):
        return self.proc is not None and self.proc.poll() is None


def open_client(port, client_id, version, username, password):
    sock = socket.create_connection(("127.0.0.1", port), 3)
    sock.settimeout(3)
    sock.sendall(connect_packet(client_id, version, username, password))
    try:
        ptype, body = read_packet(sock)
    except (ConnectionError, socket.timeout):
        sock.close()
        return None, None
    if ptype != 0x20 or reason_of_connack(body) != 0:
        sock.close()
        return None, reason_of_connack(body) if ptype == 0x20 else None
    return sock, 0


def expect(cond, message):
    if not cond:
        raise AssertionError(message)


def integration(binary, port):
    broker = Broker(binary, port)
    broker.start()
    try:
        anon, _ = open_client(port, "anon", 5, None, None)
        expect(anon is None, "anonymous CONNECT was accepted")

        ok, reason = open_client(port, "ok-client", 5, USER, PASSWORD)
        expect(ok is not None, f"credentialed CONNECT failed ({reason})")
        ok.sendall(subscribe_packet(5, 1, "ok-topic", True))
        ptype, body = read_packet(ok)
        expect(ptype == 0x90 and suback_granted(body), "well-formed SUBSCRIBE was not granted")

        pub, reason = open_client(port, "pub-client", 5, USER, PASSWORD)
        expect(pub is not None, f"publisher CONNECT failed ({reason})")
        pub.sendall(publish_packet(5, "ok-topic", b"ping"))
        ptype, body = read_packet(ok)
        expect(ptype == 0x30 and b"ping" in body, "well-formed subscription did not deliver")
        ok.close()
        pub.close()

        problems = []
        for version, topic in ((5, "bad-v5"), (4, "bad-v311")):
            client, reason = open_client(port, f"bad-{version}", version, USER, PASSWORD)
            expect(client is not None, f"v{version} CONNECT failed ({reason})")
            client.sendall(subscribe_packet(version, 7, topic, False))
            granted = False
            delivered = False
            try:
                ptype, body = read_packet(client)
                if ptype == 0x90 and suback_granted(body):
                    granted = True
                publisher, _ = open_client(port, f"pub-{version}", version, USER, PASSWORD)
                if publisher is not None:
                    publisher.sendall(publish_packet(version, topic, b"leak"))
                    publisher.close()
                    client.settimeout(1)
                    ptype, body = read_packet(client)
                    if ptype == 0x30 and b"leak" in body:
                        delivered = True
            except (ConnectionError, socket.timeout):
                pass
            client.close()
            if granted or delivered:
                problems.append(
                    f"MQTT v{version} SUBSCRIBE without an options byte was accepted "
                    f"(suback={granted}, delivered={delivered})"
                )

        exact_topic = "e" * 1019
        client, _ = open_client(port, "exact", 5, USER, PASSWORD)
        expect(client is not None, "CONNECT before exact-size packet failed")
        client.sendall(subscribe_packet(5, 9, exact_topic, False))
        try:
            read_packet(client)
        except (ConnectionError, socket.timeout, OSError):
            pass
        time.sleep(0.3)
        err = ""
        alive = broker.alive()
        if not alive:
            err = broker.stop()
        if (not alive) or ("heap-buffer-overflow" in err):
            problems.append(
                "exact-size SUBSCRIBE without an options byte overflowed the message buffer"
            )
        if problems:
            raise AssertionError("; ".join(problems))
    finally:
        if broker.alive():
            text = broker.stop()
            if "heap-buffer-overflow" in text:
                raise AssertionError(
                    "broker reported a heap-buffer-overflow while handling SUBSCRIBE"
                )


def main():
    version = image_version()
    print(f"broker image version {version}")
    binary, library, src = ensure_broker(version)
    unit = compile_unit(library, src)
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:detect_leaks=0"
    failed = []
    for mode in MODES:
        result = subprocess.run([str(unit), mode], env=env, capture_output=True, text=True)
        sys.stderr.write(result.stderr)
        if result.returncode != 0:
            failed.append(f"{mode} exited {result.returncode}")
    try:
        integration(binary, 18830)
    except AssertionError as exc:
        failed.append(str(exc))
    if failed:
        print("FAILED:")
        for item in failed:
            print(f"  {item}")
        return 1
    print("malformed SUBSCRIBE packets were rejected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
