# services.py

import os
import random
import string
import socket
import threading
import json
import time
import ipaddress
from datetime import datetime, timezone

import whois
import geoip2.database

import core_state as st

# DNS deps (copiado de dnslistener.py)
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE, RCODE


def sanitize_session_name(name: str) -> str:
    if not name:
        return ""
    out = []
    for ch in name.strip():
        if ch.isalnum() or ch in ("_", "-", "."):
            out.append(ch)
        else:
            out.append("_")
    s = "".join(out).strip("._-")
    return s[:120] if s else ""


def resolve_persist_path(persist_arg: str | None):
    if not persist_arg:
        return None
    s = str(persist_arg).strip()
    if not s:
        return None
    s_expanded = os.path.expanduser(s)
    _, ext = os.path.splitext(s_expanded.lower())
    looks_like_path = (os.sep in s_expanded) or ("/" in s_expanded) or ("\\" in s_expanded) or (ext == ".jsonl")
    if looks_like_path:
        path = os.path.abspath(s_expanded)
        if not path.lower().endswith(".jsonl"):
            path = path + ".jsonl"
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        return path
    safe = sanitize_session_name(s_expanded)
    if not safe:
        return None
    os.makedirs("sessions", exist_ok=True)
    return os.path.abspath(os.path.join("sessions", f"{safe}.jsonl"))


def init_persist(session_or_path: str | None):
    st.PERSIST_PATH = resolve_persist_path(session_or_path)
    load_persist()


def load_persist():
    if not st.PERSIST_PATH or not os.path.exists(st.PERSIST_PATH):
        return
    loaded = []
    try:
        with open(st.PERSIST_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        loaded.append(obj)
                except Exception:
                    continue
    except Exception:
        return
    if loaded:
        if len(loaded) > st.MAX_LOGS:
            loaded = loaded[-st.MAX_LOGS:]
        st.LOGS.clear()
        st.LOGS.extend(loaded)


def persist_append(log: dict):
    if not st.PERSIST_PATH:
        return
    try:
        rec = dict(log)
        line = json.dumps(rec, ensure_ascii=False)
        with st.PERSIST_LOCK:
            with open(st.PERSIST_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        return


def init_geoip():
    try:
        st.GEOIP_READER = geoip2.database.Reader(st.GEOIP_DB_PATH)
    except Exception:
        st.GEOIP_READER = None


def geoip_country(ip: str):
    if ip in st.GEOIP_CACHE:
        return st.GEOIP_CACHE[ip]
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            st.GEOIP_CACHE[ip] = None
            return None
    except ValueError:
        st.GEOIP_CACHE[ip] = None
        return None
    if st.GEOIP_READER is None:
        st.GEOIP_CACHE[ip] = None
        return None
    try:
        resp = st.GEOIP_READER.country(ip)
        code = resp.country.iso_code
        if isinstance(code, str) and len(code) == 2:
            code = code.upper()
            st.GEOIP_CACHE[ip] = code
            return code
        st.GEOIP_CACHE[ip] = None
        return None
    except Exception:
        st.GEOIP_CACHE[ip] = None
        return None


def log_headers_to_file(req, path):
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "path": f"/{path}",
        "ip": req.remote_addr,
        "method": req.method,
        "headers": {k: v for k, v in req.headers.items()}
    }
    try:
        with open(st.HEADER_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    except Exception:
        return


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _safe_get_body(req):
    try:
        raw = req.get_data(cache=False)
        if not raw:
            return ""
        if len(raw) > st.MAX_BODY_BYTES:
            raw = raw[:st.MAX_BODY_BYTES]
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return raw.decode(errors="replace")
    except Exception:
        return ""


def _build_request_raw(req, body_text: str):
    try:
        proto = req.environ.get("SERVER_PROTOCOL", "HTTP/1.1")
        line = f"{req.method} {req.full_path if req.query_string else req.path} {proto}".rstrip()
        headers = "\n".join([f"{k}: {v}" for k, v in req.headers.items()])
        if body_text:
            return f"{line}\n{headers}\n\n{body_text}"
        return f"{line}\n{headers}\n"
    except Exception:
        return ""


def _build_response_raw(status_code: int, headers: dict, body: str):
    try:
        reason = "OK"
        if status_code == 302:
            reason = "FOUND"
        elif status_code == 404:
            reason = "NOT FOUND"
        elif status_code == 500:
            reason = "INTERNAL SERVER ERROR"
        start = f"HTTP/1.1 {status_code} {reason}"
        hdrs = "\n".join([f"{k}: {v}" for k, v in headers.items()])
        if body:
            return f"{start}\n{hdrs}\n\n{body}"
        return f"{start}\n{hdrs}\n"
    except Exception:
        return ""


def parse_request_data(req):
    try:
        ip = req.headers.get("cf-connecting-ip") or req.remote_addr or ""
        try:
            listener_port = int(req.environ.get("SERVER_PORT", 0))
        except (TypeError, ValueError):
            listener_port = None
        country = geoip_country(ip)
        body = _safe_get_body(req)
        request_raw = _build_request_raw(req, body)
        data = {
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"),
            "ip": ip,
            "proto": "HTTPS" if req.is_secure else "HTTP",
            "method": req.method,
            "path": req.path,
            "headers": dict(req.headers),
            "body": body,
            "listener_port": listener_port,
            "country": country,
            "request_raw": request_raw,
            "response_raw": ""
        }
        return data
    except Exception as e:
        if st.VERBOSE_LEVEL >= 2:
            print(f"{st.C['RED']}[!] Error parsing request: {e}{st.C['RESET']}")
        return {}


def log_to_console(log):
    if st.VERBOSE_LEVEL <= 0:
        return

    if st.VERBOSE_LEVEL == 1:
        print("NEW REQUEST RECEIVED")
        print(f"TIME: {log.get('time', '')}")
        print(f"IP: {log.get('ip', '')}")
        port = log.get("listener_port")
        if port:
            print(f"PORT: {port}")
        print(f"PROTO: {log.get('proto', 'HTTP')}")
        print(f"METHOD: {log.get('method', '')}")
        print(f"PATH: {log.get('path', '')}")
        print("")
        return

    print(f"{st.C['YELLOW']}{'=' * 71}{st.C['RESET']}")
    print(f"{st.C['MAGENTA']}NEW REQUEST RECEIVED{st.C['RESET']}")
    print(f"{st.C['BLUE']}TIME: {log.get('time', '')}{st.C['RESET']}")
    print(f"{st.C['BLUE']}IP: {log.get('ip', '')}{st.C['RESET']}")
    port = log.get("listener_port")
    if port:
        print(f"{st.C['BLUE']}PORT: {port}{st.C['RESET']}")
    print(f"{st.C['BLUE']}PROTO: {log.get('proto', 'HTTP')}{st.C['RESET']}")
    print(f"{st.C['GREEN']}METHOD: {log.get('method', '')}{st.C['RESET']}")
    print(f"{st.C['MAGENTA']}PATH: {log.get('path', '')}{st.C['RESET']}")

    if log.get("event") == "open_redirect":
        print(f"{st.C['RED']}[!] FOLLOW REDIRECT → {log.get('redirect_to', '')}{st.C['RESET']}")

    print(f"{st.C['MAGENTA']}REQUEST:{st.C['RESET']}")
    print(log.get("request_raw") or "(empty)")
    print(f"{st.C['MAGENTA']}RESPONSE:{st.C['RESET']}")
    print(log.get("response_raw") or "(empty)")
    print(f"{st.C['YELLOW']}{'=' * 71}{st.C['RESET']}")


def store_log_in_memory(log):
    if len(st.LOGS) >= st.MAX_LOGS:
        st.LOGS.pop(0)
    st.LOGS.append(log)
    persist_append(log)


def _whois_worker(ip: str, out: dict):
    try:
        w = whois.whois(ip)
        raw = getattr(w, "text", None)
        if isinstance(raw, list):
            raw = "\n".join(raw)
        if not isinstance(raw, str) or not raw.strip():
            parts = []
            if hasattr(w, "items"):
                for k, v in w.items():
                    if not v:
                        continue
                    if isinstance(v, (list, tuple, set)):
                        v = ", ".join(str(x) for x in v)
                    parts.append(f"{k}: {v}")
            raw = "\n".join(parts) or "(WHOIS sin datos)"
        out["ok"] = True
        out["text"] = f"IP: {ip}\n\n{raw}"
    except Exception as e:
        out["ok"] = False
        out["error"] = str(e)


def whois_cached(ip: str):
    now = time.time()
    with st.WHOIS_LOCK:
        hit = st.WHOIS_CACHE.get(ip)
        if hit and (now - hit["ts"] < st.WHOIS_TTL):
            return {"ok": True, "text": hit["text"], "cached": True}

    out = {}
    t = threading.Thread(target=_whois_worker, args=(ip, out), daemon=True)
    t.start()
    t.join(timeout=st.WHOIS_TIMEOUT)

    if not out:
        return {"ok": False, "error": f"WHOIS timeout ({st.WHOIS_TIMEOUT}s)"}

    if out.get("ok"):
        with st.WHOIS_LOCK:
            st.WHOIS_CACHE[ip] = {"ts": now, "text": out.get("text", "")}
        return {"ok": True, "text": out.get("text", ""), "cached": False}

    return {"ok": False, "error": out.get("error", "WHOIS error")}


def _random_id(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def hosted_upload(file_path: str):
    p = os.path.expanduser(file_path.strip().strip('"').strip("'"))
    if not p:
        print("[!] Usage: file upload /path/to/file")
        return
    ap = os.path.abspath(p)
    if not os.path.isfile(ap):
        print(f"[!] File not found: {ap}")
        return
    ext = os.path.splitext(ap)[1]
    hid = _random_id(8)
    with st.HOSTED_LOCK:
        while hid in st.HOSTED_FILES:
            hid = _random_id(8)
        st.HOSTED_FILES[hid] = {"path": ap, "ext": ext}
    virtual = f"/{st.HOSTED_PREFIX}/{hid}{ext}"
    print(f"[+] Hosted file -> [ ID: {hid} ]")
    print(f" URL: {virtual}")


def hosted_unload(hid: str):
    if not hid:
        print("[!] Usage: file unload <id>")
        return
    with st.HOSTED_LOCK:
        if hid not in st.HOSTED_FILES:
            print(f"[!] Unknown id: {hid}")
            return
        st.HOSTED_FILES.pop(hid, None)
    print(f"[-] Unhosted file [ ID: {hid} ]")


def hosted_list():
    with st.HOSTED_LOCK:
        items = list(st.HOSTED_FILES.items())
    if not items:
        print("hosted files:")
        return
    print("hosted files:")
    for hid, meta in items:
        ext = meta.get("ext") or ""
        print(f" - /{st.HOSTED_PREFIX}/{hid}{ext} [id: {hid}]")


# ============================================================
# DNS LISTENER (old dnslistener.py)
# ============================================================

def dns_generate_token(n=12):
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(n))


def dns_log_query_line(client_ip: str, client_port: int, qname: str, qtype: str):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = f"{ts} src={client_ip}:{client_port} qname={qname} qtype={qtype}"

    # consola
    if st.VERBOSE_LEVEL > 0:
        print(line)

    # archivo (igual que dnslistener.py)
    try:
        with open(st.DNS_CONFIG["log_file"], "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def dns_save_seen_token(qname: str, client_ip: str):
    token = qname.split(".")[0]

    with st.DNS_SEEN_LOCK:
        try:
            with open(st.DNS_CONFIG["seen_file"], "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    data = {}
        except Exception:
            data = {}

        if token in data:
            return

        data[token] = {
            "first_seen": time.time(),
            "source_ip": client_ip
        }

        try:
            with open(st.DNS_CONFIG["seen_file"], "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            return


def dns_build_response(request: DNSRecord, config: dict):
    reply = DNSRecord(
        DNSHeader(
            id=request.header.id,
            qr=1,
            aa=1,
            ra=0
        ),
        q=request.q
    )

    if config.get("mode") == "NXDOMAIN":
        reply.header.rcode = RCODE.NXDOMAIN
        return reply

    qtype = QTYPE[request.q.qtype]

    if qtype == "A":
        reply.add_answer(
            RR(
                rname=request.q.qname,
                rtype=QTYPE.A,
                rclass=1,
                ttl=5,
                rdata=A(config.get("reply_ip", "127.0.0.1"))
            )
        )

    return reply


def dns_handle_packet(data: bytes, addr, sock: socket.socket, config: dict):
    try:
        request = DNSRecord.parse(data)
    except Exception:
        return

    qname = str(request.q.qname).rstrip(".")
    qtype = QTYPE[request.q.qtype]
    client_ip, client_port = addr

    # Check if this is the DNS exception domain - skip logging
    if st.DNS_EXCEPTION_TOKEN and qname == f"{st.DNS_EXCEPTION_TOKEN}.{config.get('domain_base', '').strip('.')}":
        # Still respond to DNS query but don't log it
        reply = dns_build_response(request, config)
        try:
            sock.sendto(reply.pack(), addr)
        except Exception:
            pass
        return

    domain_base = (config.get("domain_base") or "").strip().strip(".")
    if domain_base:
        if not qname.endswith(domain_base):
            return

    # (1) logging legacy (archivo + consola) y tokens vistos
    dns_log_query_line(client_ip, client_port, qname, qtype)
    dns_save_seen_token(qname, client_ip)

    # (2) logging interno a Introspector (st.LOGS)
    log = {
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"),
        "ip": client_ip,
        "proto": "DNS",
        "method": "QUERY",
        "path": qname,
        "headers": {},
        "body": "",
        "listener_port": int(config.get("listen_port") or 0) or None,
        "country": geoip_country(client_ip),
        "qname": qname,
        "qtype": qtype,
        "client_port": client_port,
        "request_raw": f"QNAME {qname}\nQTYPE {qtype}\nSRC {client_ip}:{client_port}\n",
        "response_raw": ""
    }

    # respuesta DNS
    reply = dns_build_response(request, config)
    try:
        sock.sendto(reply.pack(), addr)
        # opcional
        mode = (config.get("mode") or "A").upper()
        log["response_raw"] = f"MODE {mode}\n"
        if mode == "A":
            log["response_raw"] += f"A {config.get('reply_ip', '')}\n"
        elif mode == "NXDOMAIN":
            log["response_raw"] += "RCODE NXDOMAIN\n"
    except Exception as e:
        log["response_raw"] = f"DNS send error: {e}"

    log_to_console(log)
    store_log_in_memory(log)


def _dns_udp_loop(sock: socket.socket, config: dict):
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except Exception as e:
            st.DNS_SERVER["error"] = str(e)
            continue
        dns_handle_packet(data, addr, sock, config)


def start_dns_listener():
    # evita doble bind
    if st.DNS_SERVER.get("running"):
        return True

    config = st.DNS_CONFIG
    ip_ = config.get("listen_ip", "0.0.0.0")
    port_ = int(config.get("listen_port", 53))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((ip_, port_))
    except Exception as e:
        st.DNS_SERVER["running"] = False
        st.DNS_SERVER["error"] = str(e)
        st.DNS_SERVER["sock"] = None
        st.DNS_SERVER["thread"] = None
        return False

    t = threading.Thread(target=_dns_udp_loop, args=(sock, config), daemon=True)
    t.start()

    st.DNS_SERVER["running"] = True
    st.DNS_SERVER["error"] = None
    st.DNS_SERVER["sock"] = sock
    st.DNS_SERVER["thread"] = t

    return True
