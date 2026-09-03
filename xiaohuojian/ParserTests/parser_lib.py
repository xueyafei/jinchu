#!/usr/bin/env python3
"""URI / subscription parsers mirroring Shared/*.swift for Linux tests."""
from __future__ import annotations

import base64
import json
import re
import urllib.parse
from typing import Any, Optional


def _pad_b64(s: str) -> str:
    s = s.strip().replace("\n", "").replace("\r", "")
    s += "=" * ((4 - len(s) % 4) % 4)
    return s


def b64_decode(s: str) -> bytes:
    s = _pad_b64(s)
    # urlsafe then std
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(s)
        except Exception:
            continue
    # last resort: translate
    t = s.replace("-", "+").replace("_", "/")
    return base64.b64decode(_pad_b64(t))


def b64_encode_std(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_encode_url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def split_fragment(uri: str) -> tuple[str, str]:
    if "#" in uri:
        body, frag = uri.split("#", 1)
        return body, urllib.parse.unquote(frag)
    return uri, ""


def parse_query(qs: str) -> dict[str, str]:
    if not qs:
        return {}
    if qs.startswith("?"):
        qs = qs[1:]
    out: dict[str, str] = {}
    for k, v in urllib.parse.parse_qsl(qs, keep_blank_values=True):
        out[k] = v
    return out


def _int_port(v: Any, default: int = 443) -> int:
    try:
        n = int(str(v).strip())
        if 1 <= n <= 65535:
            return n
    except Exception:
        pass
    return default


class Node(dict):
    """Dict-like node with required keys."""

    def __init__(self, **kwargs: Any):
        super().__init__()
        self.update(
            {
                "type": "",
                "name": "",
                "host": "",
                "port": 0,
                "password": "",
                "uuid": "",
                "method": "",
                "alterId": 0,
                "security": "",
                "network": "tcp",
                "tls": False,
                "sni": "",
                "hostHeader": "",
                "path": "",
                "flow": "",
                "allowInsecure": False,
                "plugin": "",
                "pluginOpts": "",
                "username": "",
                "alpn": "",
                "obfs": "",
                "obfsPassword": "",
                "encryption": "",
                "serviceName": "",
                "fingerprint": "",
                "group": "Default",
                "rawURI": "",
            }
        )
        self.update({k: v for k, v in kwargs.items() if v is not None})

    def uri(self) -> str:
        return encode_uri(self)


def parse_ss(uri: str) -> Node:
    raw = uri.strip()
    body, name = split_fragment(raw)
    if not body.lower().startswith("ss://"):
        raise ValueError("not ss://")
    rest = body[5:]
    plugin = ""
    plugin_opts = ""
    method = ""
    password = ""
    host = ""
    port = 0

    # query
    q = ""
    if "?" in rest:
        rest, q = rest.split("?", 1)
        params = parse_query(q)
        plugin = params.get("plugin", "")
        if plugin and ";" in plugin:
            plugin, plugin_opts = plugin.split(";", 1)

    userinfo = ""
    hostport = ""

    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
        # SIP002: userinfo is base64(method:password) or method:password
        decoded = None
        try:
            decoded = b64_decode(urllib.parse.unquote(userinfo)).decode("utf-8")
        except Exception:
            decoded = None
        if decoded and ":" in decoded and not userinfo.startswith("http"):
            # If original already contains ':', prefer decoded only when it looks like method:pass
            if ":" not in userinfo or re.match(r"^[A-Za-z0-9_\-+/=]+$", userinfo):
                # Could be either. Try: if decoded looks like "cipher:password"
                m = decoded.split(":", 1)
                if m[0] and ("-" in m[0] or m[0] in ("rc4", "table", "none") or "gcm" in m[0] or "poly" in m[0] or "chacha" in m[0] or "aes" in m[0]):
                    method, password = m[0], m[1]
                elif ":" in userinfo:
                    method, password = urllib.parse.unquote(userinfo).split(":", 1)
                else:
                    method, password = m[0], m[1]
            else:
                method, password = urllib.parse.unquote(userinfo).split(":", 1)
        else:
            plain = urllib.parse.unquote(userinfo)
            if ":" in plain:
                method, password = plain.split(":", 1)
            else:
                raise ValueError("ss userinfo missing password")
    else:
        # legacy ss://base64(method:password@host:port)
        blob = b64_decode(urllib.parse.unquote(rest)).decode("utf-8")
        if "@" not in blob:
            raise ValueError("legacy ss missing @")
        userinfo, hostport = blob.rsplit("@", 1)
        method, password = userinfo.split(":", 1)

    hostport = hostport.strip()
    # [ipv6]:port
    if hostport.startswith("["):
        m = re.match(r"^\[(.+)\]:(\d+)$", hostport)
        if not m:
            raise ValueError("bad ipv6 hostport")
        host, port = m.group(1), int(m.group(2))
    else:
        if ":" not in hostport:
            raise ValueError("missing port")
        host, ps = hostport.rsplit(":", 1)
        port = int(ps)

    if not name:
        name = f"{host}:{port}"
    return Node(
        type="ss",
        name=name,
        host=host,
        port=port,
        method=method,
        password=password,
        plugin=plugin,
        pluginOpts=plugin_opts,
        rawURI=raw,
    )


def encode_ss(n: Node) -> str:
    user = f"{n['method']}:{n['password']}"
    b = b64_encode_url(user.encode("utf-8"))
    host = n["host"]
    if ":" in host and not host.startswith("["):
        hp = f"[{host}]:{n['port']}"
    else:
        hp = f"{host}:{n['port']}"
    uri = f"ss://{b}@{hp}"
    q = []
    if n.get("plugin"):
        p = n["plugin"]
        if n.get("pluginOpts"):
            p = f"{p};{n['pluginOpts']}"
        q.append("plugin=" + urllib.parse.quote(p, safe=""))
    if q:
        uri += "?" + "&".join(q)
    if n.get("name"):
        uri += "#" + urllib.parse.quote(n["name"], safe="")
    return uri


def parse_vmess(uri: str) -> Node:
    raw = uri.strip()
    body, frag = split_fragment(raw)
    if not body.lower().startswith("vmess://"):
        raise ValueError("not vmess://")
    payload = body[8:]
    data = json.loads(b64_decode(payload).decode("utf-8"))
    tls_field = str(data.get("tls") or "")
    tls = tls_field.lower() in ("tls", "true", "1", "xtls", "reality")
    net = str(data.get("net") or data.get("network") or "tcp")
    name = str(data.get("ps") or data.get("remarks") or frag or "")
    host = str(data.get("add") or data.get("host") or data.get("server") or "")
    # host header vs add
    add = str(data.get("add") or "")
    host_header = str(data.get("host") or "")
    if not host:
        host = add
    if add:
        host = add
    port = _int_port(data.get("port"), 443)
    uuid = str(data.get("id") or data.get("uuid") or "")
    aid = 0
    try:
        aid = int(data.get("aid") or 0)
    except Exception:
        aid = 0
    scy = str(data.get("scy") or data.get("security") or "auto")
    path = str(data.get("path") or "")
    sni = str(data.get("sni") or "")
    alpn = str(data.get("alpn") or "")
    if not name:
        name = f"{host}:{port}"
    return Node(
        type="vmess",
        name=name,
        host=host,
        port=port,
        uuid=uuid,
        password=uuid,
        method=scy,
        alterId=aid,
        security=scy,
        network=net,
        tls=tls,
        sni=sni,
        hostHeader=host_header,
        path=path,
        alpn=alpn,
        allowInsecure=str(data.get("verify_cert") or "true").lower() in ("false", "0"),
        rawURI=raw,
    )


def encode_vmess(n: Node) -> str:
    obj = {
        "v": "2",
        "ps": n.get("name") or "",
        "add": n["host"],
        "port": str(n["port"]),
        "id": n.get("uuid") or n.get("password") or "",
        "aid": str(n.get("alterId") or 0),
        "scy": n.get("security") or n.get("method") or "auto",
        "net": n.get("network") or "tcp",
        "type": "none",
        "host": n.get("hostHeader") or "",
        "path": n.get("path") or "",
        "tls": "tls" if n.get("tls") else "",
        "sni": n.get("sni") or "",
        "alpn": n.get("alpn") or "",
    }
    b = b64_encode_std(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    return "vmess://" + b


def parse_vless(uri: str) -> Node:
    raw = uri.strip()
    body, name = split_fragment(raw)
    if not body.lower().startswith("vless://"):
        raise ValueError("not vless://")
    rest = body[8:]
    if "@" not in rest:
        raise ValueError("vless missing @")
    uuid, hostpart = rest.split("@", 1)
    uuid = urllib.parse.unquote(uuid)
    q = ""
    if "?" in hostpart:
        hostport, q = hostpart.split("?", 1)
    else:
        hostport = hostpart
    params = parse_query(q)
    if hostport.startswith("["):
        m = re.match(r"^\[(.+)\]:(\d+)$", hostport)
        if not m:
            raise ValueError("bad ipv6")
        host, port = m.group(1), int(m.group(2))
    else:
        host, ps = hostport.rsplit(":", 1)
        port = int(ps)
    security = params.get("security", "none")
    tls = security.lower() in ("tls", "xtls", "reality")
    if not name:
        name = params.get("remarks") or f"{host}:{port}"
    return Node(
        type="vless",
        name=name,
        host=host,
        port=port,
        uuid=uuid,
        password=uuid,
        encryption=params.get("encryption", "none"),
        network=params.get("type", "tcp"),
        tls=tls,
        security=security,
        sni=params.get("sni") or params.get("peer") or "",
        hostHeader=params.get("host") or "",
        path=params.get("path") or "",
        flow=params.get("flow") or "",
        allowInsecure=params.get("allowInsecure", "0") in ("1", "true", "True"),
        alpn=params.get("alpn") or "",
        serviceName=params.get("serviceName") or "",
        fingerprint=params.get("fp") or "",
        rawURI=raw,
    )


def encode_vless(n: Node) -> str:
    host = n["host"]
    hp = f"[{host}]:{n['port']}" if ":" in host and not host.startswith("[") else f"{host}:{n['port']}"
    q = {
        "type": n.get("network") or "tcp",
        "security": n.get("security") or ("tls" if n.get("tls") else "none"),
        "encryption": n.get("encryption") or "none",
    }
    if n.get("sni"):
        q["sni"] = n["sni"]
    if n.get("hostHeader"):
        q["host"] = n["hostHeader"]
    if n.get("path"):
        q["path"] = n["path"]
    if n.get("flow"):
        q["flow"] = n["flow"]
    if n.get("allowInsecure"):
        q["allowInsecure"] = "1"
    if n.get("alpn"):
        q["alpn"] = n["alpn"]
    if n.get("serviceName"):
        q["serviceName"] = n["serviceName"]
    if n.get("fingerprint"):
        q["fp"] = n["fingerprint"]
    qs = urllib.parse.urlencode({k: v for k, v in q.items() if v not in ("", None)})
    uri = f"vless://{n.get('uuid') or n.get('password')}@{hp}?{qs}"
    if n.get("name"):
        uri += "#" + urllib.parse.quote(n["name"], safe="")
    return uri


def parse_trojan(uri: str) -> Node:
    raw = uri.strip()
    body, name = split_fragment(raw)
    low = body.lower()
    if not (low.startswith("trojan://") or low.startswith("trojan-go://")):
        raise ValueError("not trojan://")
    rest = body.split("://", 1)[1]
    if "@" not in rest:
        raise ValueError("trojan missing @")
    password, hostpart = rest.split("@", 1)
    password = urllib.parse.unquote(password)
    q = ""
    if "?" in hostpart:
        hostport, q = hostpart.split("?", 1)
    else:
        hostport = hostpart
    params = parse_query(q)
    if hostport.startswith("["):
        m = re.match(r"^\[(.+)\]:(\d+)$", hostport)
        host, port = m.group(1), int(m.group(2))
    else:
        host, ps = hostport.rsplit(":", 1)
        port = int(ps)
    if not name:
        name = params.get("remarks") or f"{host}:{port}"
    security = params.get("security") or "tls"
    net = params.get("type") or params.get("network") or "tcp"
    return Node(
        type="trojan",
        name=name,
        host=host,
        port=port,
        password=password,
        network=net,
        tls=True,
        security=security,
        sni=params.get("sni") or params.get("peer") or "",
        hostHeader=params.get("host") or "",
        path=params.get("path") or "",
        allowInsecure=params.get("allowInsecure", "0") in ("1", "true", "True")
        or params.get("skipVerify", "0") in ("1", "true"),
        alpn=params.get("alpn") or "",
        rawURI=raw,
    )


def encode_trojan(n: Node) -> str:
    host = n["host"]
    hp = f"[{host}]:{n['port']}" if ":" in host and not host.startswith("[") else f"{host}:{n['port']}"
    q = {"security": "tls", "type": n.get("network") or "tcp"}
    if n.get("sni"):
        q["sni"] = n["sni"]
    if n.get("allowInsecure"):
        q["allowInsecure"] = "1"
    if n.get("hostHeader"):
        q["host"] = n["hostHeader"]
    if n.get("path"):
        q["path"] = n["path"]
    if n.get("alpn"):
        q["alpn"] = n["alpn"]
    qs = urllib.parse.urlencode({k: v for k, v in q.items() if v})
    uri = f"trojan://{urllib.parse.quote(n['password'], safe='')}@{hp}?{qs}"
    if n.get("name"):
        uri += "#" + urllib.parse.quote(n["name"], safe="")
    return uri


def parse_hysteria2(uri: str) -> Node:
    raw = uri.strip()
    body, name = split_fragment(raw)
    low = body.lower()
    if low.startswith("hysteria2://"):
        rest = body[12:]
    elif low.startswith("hy2://"):
        rest = body[6:]
    else:
        raise ValueError("not hysteria2://")
    if "@" not in rest:
        raise ValueError("hy2 missing @")
    password, hostpart = rest.split("@", 1)
    password = urllib.parse.unquote(password)
    q = ""
    if "?" in hostpart:
        hostport, q = hostpart.split("?", 1)
    else:
        hostport = hostpart
    params = parse_query(q)
    if hostport.startswith("["):
        m = re.match(r"^\[(.+)\]:(\d+)$", hostport)
        host, port = m.group(1), int(m.group(2))
    else:
        # port optional? default 443
        if ":" in hostport:
            host, ps = hostport.rsplit(":", 1)
            port = int(ps)
        else:
            host, port = hostport, 443
    if not name:
        name = f"{host}:{port}"
    insecure = params.get("insecure", "0") in ("1", "true", "True")
    return Node(
        type="hysteria2",
        name=name,
        host=host,
        port=port,
        password=password,
        tls=True,
        sni=params.get("sni") or "",
        allowInsecure=insecure,
        obfs=params.get("obfs") or "",
        obfsPassword=params.get("obfs-password") or params.get("obfsPassword") or "",
        alpn=params.get("alpn") or "",
        rawURI=raw,
    )


def encode_hysteria2(n: Node) -> str:
    host = n["host"]
    hp = f"[{host}]:{n['port']}" if ":" in host and not host.startswith("[") else f"{host}:{n['port']}"
    q = {}
    if n.get("sni"):
        q["sni"] = n["sni"]
    if n.get("allowInsecure"):
        q["insecure"] = "1"
    if n.get("obfs"):
        q["obfs"] = n["obfs"]
    if n.get("obfsPassword"):
        q["obfs-password"] = n["obfsPassword"]
    if n.get("alpn"):
        q["alpn"] = n["alpn"]
    qs = urllib.parse.urlencode(q) if q else ""
    uri = f"hysteria2://{urllib.parse.quote(n['password'], safe='')}@{hp}"
    if qs:
        uri += "?" + qs
    if n.get("name"):
        uri += "#" + urllib.parse.quote(n["name"], safe="")
    return uri


def parse_socks(uri: str) -> Node:
    raw = uri.strip()
    body, name = split_fragment(raw)
    low = body.lower()
    if low.startswith("socks5://"):
        rest = body[9:]
        typ = "socks"
    elif low.startswith("socks://"):
        rest = body[8:]
        typ = "socks"
    elif low.startswith("socks5h://"):
        rest = body[10:]
        typ = "socks"
    else:
        raise ValueError("not socks://")
    username = ""
    password = ""
    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
        userinfo = urllib.parse.unquote(userinfo)
        if ":" in userinfo:
            username, password = userinfo.split(":", 1)
        else:
            username = userinfo
    else:
        hostport = rest
    if hostport.startswith("["):
        m = re.match(r"^\[(.+)\]:(\d+)$", hostport)
        host, port = m.group(1), int(m.group(2))
    else:
        if ":" not in hostport:
            raise ValueError("missing port")
        host, ps = hostport.rsplit(":", 1)
        port = int(ps)
    if not name:
        name = f"{host}:{port}"
    return Node(
        type=typ,
        name=name,
        host=host,
        port=port,
        username=username,
        password=password,
        rawURI=raw,
    )


def encode_socks(n: Node) -> str:
    host = n["host"]
    hp = f"[{host}]:{n['port']}" if ":" in host and not host.startswith("[") else f"{host}:{n['port']}"
    auth = ""
    if n.get("username"):
        auth = urllib.parse.quote(n["username"], safe="")
        if n.get("password"):
            auth += ":" + urllib.parse.quote(n["password"], safe="")
        auth += "@"
    uri = f"socks5://{auth}{hp}"
    if n.get("name"):
        uri += "#" + urllib.parse.quote(n["name"], safe="")
    return uri


def parse_http(uri: str) -> Node:
    raw = uri.strip()
    body, name = split_fragment(raw)
    low = body.lower()
    if low.startswith("https://"):
        rest = body[8:]
        tls = True
        typ = "http"
    elif low.startswith("http://"):
        rest = body[7:]
        tls = False
        typ = "http"
    else:
        raise ValueError("not http://")
    username = ""
    password = ""
    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
        userinfo = urllib.parse.unquote(userinfo)
        if ":" in userinfo:
            username, password = userinfo.split(":", 1)
        else:
            username = userinfo
    else:
        hostport = rest
    # strip path
    if "/" in hostport:
        hostport = hostport.split("/", 1)[0]
    if hostport.startswith("["):
        m = re.match(r"^\[(.+)\]:(\d+)$", hostport)
        host, port = m.group(1), int(m.group(2))
    else:
        if ":" not in hostport:
            raise ValueError("http proxy missing port")
        host, ps = hostport.rsplit(":", 1)
        port = int(ps)
    if not name:
        name = f"{host}:{port}"
    return Node(
        type=typ,
        name=name,
        host=host,
        port=port,
        username=username,
        password=password,
        tls=tls,
        rawURI=raw,
    )


def encode_http(n: Node) -> str:
    scheme = "https" if n.get("tls") else "http"
    host = n["host"]
    hp = f"[{host}]:{n['port']}" if ":" in host and not host.startswith("[") else f"{host}:{n['port']}"
    auth = ""
    if n.get("username"):
        auth = urllib.parse.quote(n["username"], safe="")
        if n.get("password"):
            auth += ":" + urllib.parse.quote(n["password"], safe="")
        auth += "@"
    uri = f"{scheme}://{auth}{hp}"
    if n.get("name"):
        uri += "#" + urllib.parse.quote(n["name"], safe="")
    return uri


PARSERS = {
    "ss": parse_ss,
    "vmess": parse_vmess,
    "vless": parse_vless,
    "trojan": parse_trojan,
    "trojan-go": parse_trojan,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "socks": parse_socks,
    "socks5": parse_socks,
    "socks5h": parse_socks,
    "http": parse_http,
    "https": parse_http,
}


def parse_uri(uri: str) -> Node:
    uri = uri.strip()
    if not uri or uri.startswith("#"):
        raise ValueError("empty")
    scheme = uri.split(":", 1)[0].lower()
    if scheme not in PARSERS:
        raise ValueError(f"unsupported scheme {scheme}")
    n = PARSERS[scheme](uri)
    if not n["host"] or not n["port"]:
        raise ValueError("missing host/port")
    return n


def encode_uri(n: Node) -> str:
    t = n["type"]
    if t == "ss":
        return encode_ss(n)
    if t == "vmess":
        return encode_vmess(n)
    if t == "vless":
        return encode_vless(n)
    if t == "trojan":
        return encode_trojan(n)
    if t == "hysteria2":
        return encode_hysteria2(n)
    if t == "socks":
        return encode_socks(n)
    if t == "http":
        return encode_http(n)
    raise ValueError(f"cannot encode {t}")


def parse_many_uris(text: str) -> list[Node]:
    nodes: list[Node] = []
    for line in text.replace("\r", "\n").split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            nodes.append(parse_uri(line))
        except Exception:
            continue
    return nodes


def parse_subscription_body(body: str, group: str = "订阅") -> list[Node]:
    text = body.strip()
    if not text:
        return []

    # SIP008 JSON
    if text.startswith("{") or text.startswith("["):
        try:
            data = json.loads(text)
            nodes = parse_sip008(data, group)
            if nodes:
                return nodes
        except Exception:
            pass

    # Clash YAML
    if "proxies:" in text or text.lstrip().startswith("mixed-port:") or "proxy-groups:" in text:
        try:
            nodes = parse_clash_yaml(text, group)
            if nodes:
                return nodes
        except Exception:
            pass

    # base64 list of URIs
    decoded = None
    compact = re.sub(r"\s+", "", text)
    try:
        decoded = b64_decode(compact).decode("utf-8")
    except Exception:
        decoded = None
    if decoded and ("://" in decoded):
        nodes = parse_many_uris(decoded)
        for n in nodes:
            n["group"] = group
        if nodes:
            return nodes

    nodes = parse_many_uris(text)
    for n in nodes:
        n["group"] = group
    return nodes


def parse_sip008(data: Any, group: str = "SIP008") -> list[Node]:
    servers = []
    if isinstance(data, dict):
        servers = data.get("servers") or data.get("proxies") or []
    elif isinstance(data, list):
        servers = data
    nodes: list[Node] = []
    for s in servers:
        if not isinstance(s, dict):
            continue
        # SIP008 ss
        if "server" in s and ("method" in s or "cipher" in s):
            host = str(s.get("server") or s.get("host") or "")
            port = _int_port(s.get("server_port") or s.get("port"), 8388)
            method = str(s.get("method") or s.get("cipher") or "")
            password = str(s.get("password") or "")
            name = str(s.get("remarks") or s.get("name") or f"{host}:{port}")
            if host and method:
                nodes.append(
                    Node(
                        type="ss",
                        name=name,
                        host=host,
                        port=port,
                        method=method,
                        password=password,
                        plugin=str(s.get("plugin") or ""),
                        pluginOpts=str(s.get("plugin_opts") or s.get("plugin-opts") or ""),
                        group=group,
                    )
                )
                continue
        # generic typed
        t = str(s.get("type") or "").lower()
        if t:
            n = clash_proxy_to_node(s, group)
            if n:
                nodes.append(n)
    return nodes


def _unquote_yaml_scalar(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        inner = s[1:-1]
        if s[0] == '"':
            inner = inner.replace('\\"', '"').replace("\\n", "\n")
        return inner
    if " #" in s:
        s = s.split(" #", 1)[0].rstrip()
    return s


def _parse_flow_map(s: str) -> dict[str, str]:
    s = s.strip()
    if s.startswith("{") and s.endswith("}"):
        s = s[1:-1]
    out: dict[str, str] = {}
    # split on commas not in quotes
    cur = ""
    q = None
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
            continue
        if ch in ('"', "'"):
            q = ch
            cur += ch
            continue
        if ch == ",":
            if ":" in cur:
                k, v = cur.split(":", 1)
                out[k.strip()] = _unquote_yaml_scalar(v)
            cur = ""
        else:
            cur += ch
    if cur.strip() and ":" in cur:
        k, v = cur.split(":", 1)
        out[k.strip()] = _unquote_yaml_scalar(v)
    return out


def parse_clash_yaml(text: str, group: str = "Clash") -> list[Node]:
    """Minimal YAML subset parser for Clash `proxies:` list."""
    lines = text.replace("\t", "    ").splitlines()
    in_proxies = False
    proxies_indent = None
    items: list[dict] = []
    current: Optional[dict] = None
    item_indent = None

    def flush():
        nonlocal current
        if current:
            items.append(current)
            current = None

    for raw in lines:
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()

        if not in_proxies:
            if stripped == "proxies:" or stripped.startswith("proxies:"):
                in_proxies = True
                proxies_indent = indent
                rest = stripped[len("proxies:") :].strip()
                if rest.startswith("[") or rest.startswith("-"):
                    # inline list — rare
                    pass
            continue

        if proxies_indent is not None and indent <= proxies_indent and not stripped.startswith("-"):
            # left the proxies block
            flush()
            break

        if stripped.startswith("- ") or stripped == "-":
            flush()
            current = {}
            item_indent = indent
            after = stripped[1:].strip()
            if after.startswith("{"):
                current.update(_parse_flow_map(after))
            elif after and ":" in after:
                k, v = after.split(":", 1)
                current[k.strip()] = _unquote_yaml_scalar(v)
            continue

        if current is None:
            continue
        if ":" in stripped:
            k, v = stripped.split(":", 1)
            key = k.strip()
            val = v.strip()
            if val == "" or val in ("|", ">"):
                current[key] = ""
            else:
                current[key] = _unquote_yaml_scalar(val)

    flush()
    nodes: list[Node] = []
    for it in items:
        n = clash_proxy_to_node(it, group)
        if n:
            nodes.append(n)
    return nodes


def clash_proxy_to_node(p: dict, group: str) -> Optional[Node]:
    t = str(p.get("type") or "").lower().strip()
    name = str(p.get("name") or "")
    host = str(p.get("server") or p.get("host") or "")
    port = _int_port(p.get("port"), 0)
    if not t or not host or not port:
        return None
    tls = str(p.get("tls") or "").lower() in ("true", "1", "yes")
    skip = str(p.get("skip-cert-verify") or p.get("skip_cert_verify") or "").lower() in (
        "true",
        "1",
        "yes",
    )
    network = str(p.get("network") or p.get("net") or "tcp")
    sni = str(p.get("sni") or p.get("servername") or p.get("server-name") or "")
    # ws-opts
    path = ""
    host_header = ""
    ws = p.get("ws-opts") or p.get("ws_opts") or {}
    if isinstance(ws, dict):
        path = str(ws.get("path") or "")
        headers = ws.get("headers") or {}
        if isinstance(headers, dict):
            host_header = str(headers.get("Host") or headers.get("host") or "")
    path = str(p.get("path") or path or "")
    host_header = str(p.get("ws-host") or host_header or "")

    if t in ("ss", "shadowsocks"):
        return Node(
            type="ss",
            name=name or f"{host}:{port}",
            host=host,
            port=port,
            method=str(p.get("cipher") or p.get("method") or ""),
            password=str(p.get("password") or ""),
            plugin=str(p.get("plugin") or ""),
            pluginOpts=str(p.get("plugin-opts") or p.get("plugin_opts") or ""),
            group=group,
        )
    if t == "vmess":
        uuid = str(p.get("uuid") or "")
        aid = 0
        try:
            aid = int(p.get("alterId") or p.get("alterid") or 0)
        except Exception:
            aid = 0
        return Node(
            type="vmess",
            name=name or f"{host}:{port}",
            host=host,
            port=port,
            uuid=uuid,
            password=uuid,
            alterId=aid,
            security=str(p.get("cipher") or p.get("security") or "auto"),
            network=network,
            tls=tls,
            sni=sni,
            hostHeader=host_header,
            path=path,
            allowInsecure=skip,
            group=group,
        )
    if t == "vless":
        uuid = str(p.get("uuid") or "")
        return Node(
            type="vless",
            name=name or f"{host}:{port}",
            host=host,
            port=port,
            uuid=uuid,
            password=uuid,
            encryption=str(p.get("encryption") or "none"),
            network=network,
            tls=tls or str(p.get("tls") or "").lower() in ("true", "1") or bool(p.get("reality-opts")),
            security="reality" if p.get("reality-opts") else ("tls" if tls else "none"),
            sni=sni,
            hostHeader=host_header,
            path=path,
            flow=str(p.get("flow") or ""),
            allowInsecure=skip,
            group=group,
        )
    if t == "trojan":
        return Node(
            type="trojan",
            name=name or f"{host}:{port}",
            host=host,
            port=port,
            password=str(p.get("password") or ""),
            network=network,
            tls=True,
            sni=sni,
            hostHeader=host_header,
            path=path,
            allowInsecure=skip,
            group=group,
        )
    if t in ("hysteria2", "hy2"):
        return Node(
            type="hysteria2",
            name=name or f"{host}:{port}",
            host=host,
            port=port,
            password=str(p.get("password") or p.get("auth") or ""),
            tls=True,
            sni=sni,
            allowInsecure=skip,
            obfs=str(p.get("obfs") or ""),
            obfsPassword=str(p.get("obfs-password") or ""),
            group=group,
        )
    if t in ("socks", "socks5"):
        return Node(
            type="socks",
            name=name or f"{host}:{port}",
            host=host,
            port=port,
            username=str(p.get("username") or p.get("user") or ""),
            password=str(p.get("password") or ""),
            group=group,
        )
    if t in ("http", "https"):
        return Node(
            type="http",
            name=name or f"{host}:{port}",
            host=host,
            port=port,
            username=str(p.get("username") or ""),
            password=str(p.get("password") or ""),
            tls=t == "https" or tls,
            group=group,
        )
    return None


def node_key_fields(n: Node) -> dict:
    return {
        "type": n["type"],
        "host": n["host"],
        "port": int(n["port"]),
        "password": n.get("password") or "",
        "uuid": n.get("uuid") or "",
        "method": n.get("method") or "",
    }
