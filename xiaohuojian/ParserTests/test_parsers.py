#!/usr/bin/env python3
"""Linux-side tests for ss/vmess/vless/trojan/hy2/socks/http + subscriptions."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from parser_lib import (  # noqa: E402
    Node,
    b64_encode_std,
    encode_uri,
    parse_clash_yaml,
    parse_sip008,
    parse_subscription_body,
    parse_uri,
)


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


class SSTests(unittest.TestCase):
    def test_sip002_base64_userinfo(self):
        uri = "ss://" + b64("chacha20-ietf-poly1305:p@ss:w0rd") + "@203.0.113.10:8388#Tokyo"
        n = parse_uri(uri)
        self.assertEqual(n["type"], "ss")
        self.assertEqual(n["host"], "203.0.113.10")
        self.assertEqual(n["port"], 8388)
        self.assertEqual(n["method"], "chacha20-ietf-poly1305")
        self.assertEqual(n["password"], "p@ss:w0rd")
        self.assertEqual(n["name"], "Tokyo")

    def test_legacy_full_base64(self):
        inner = "aes-256-gcm:secret42@198.51.100.7:443"
        uri = "ss://" + b64(inner) + "#Legacy%20Node"
        n = parse_uri(uri)
        self.assertEqual(n["type"], "ss")
        self.assertEqual(n["host"], "198.51.100.7")
        self.assertEqual(n["port"], 443)
        self.assertEqual(n["method"], "aes-256-gcm")
        self.assertEqual(n["password"], "secret42")
        self.assertEqual(n["name"], "Legacy Node")

    def test_plain_userinfo(self):
        uri = "ss://aes-256-gcm:hello@10.0.0.2:8388#plain"
        n = parse_uri(uri)
        self.assertEqual(n["method"], "aes-256-gcm")
        self.assertEqual(n["password"], "hello")
        self.assertEqual(n["host"], "10.0.0.2")

    def test_plugin_query(self):
        user = b64("aes-256-gcm:abc")
        uri = f"ss://{user}@example.com:443?plugin=obfs-local%3Bobfs%3Dhttp#plug"
        n = parse_uri(uri)
        self.assertEqual(n["plugin"], "obfs-local")
        self.assertIn("obfs=http", n["pluginOpts"])

    def test_ss_roundtrip(self):
        orig = parse_uri("ss://aes-256-gcm:s3cret@203.0.113.8:8388#RT")
        again = parse_uri(encode_uri(orig))
        self.assertEqual(again["type"], "ss")
        self.assertEqual(again["host"], orig["host"])
        self.assertEqual(again["port"], orig["port"])
        self.assertEqual(again["method"], orig["method"])
        self.assertEqual(again["password"], orig["password"])
        self.assertEqual(again["name"], orig["name"])


class VmessTests(unittest.TestCase):
    def test_standard_json(self):
        obj = {
            "v": "2",
            "ps": "HK-VM",
            "add": "vm.example.net",
            "port": "443",
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": "vm.example.net",
            "path": "/v2",
            "tls": "tls",
            "sni": "vm.example.net",
        }
        uri = "vmess://" + b64(json.dumps(obj, separators=(",", ":")))
        n = parse_uri(uri)
        self.assertEqual(n["type"], "vmess")
        self.assertEqual(n["name"], "HK-VM")
        self.assertEqual(n["host"], "vm.example.net")
        self.assertEqual(n["port"], 443)
        self.assertEqual(n["uuid"], "550e8400-e29b-41d4-a716-446655440000")
        self.assertEqual(n["network"], "ws")
        self.assertTrue(n["tls"])
        self.assertEqual(n["path"], "/v2")
        self.assertEqual(n["sni"], "vm.example.net")

    def test_port_as_int(self):
        obj = {
            "v": "2",
            "ps": "intport",
            "add": "1.2.3.4",
            "port": 10086,
            "id": "11111111-1111-1111-1111-111111111111",
            "aid": 0,
            "net": "tcp",
            "tls": "",
        }
        n = parse_uri("vmess://" + b64(json.dumps(obj)))
        self.assertEqual(n["port"], 10086)
        self.assertFalse(n["tls"])

    def test_vmess_roundtrip(self):
        obj = {
            "v": "2",
            "ps": "RT-VM",
            "add": "10.1.2.3",
            "port": "8443",
            "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "aid": "0",
            "scy": "auto",
            "net": "tcp",
            "tls": "tls",
            "sni": "rt.example",
            "host": "",
            "path": "",
        }
        n = parse_uri("vmess://" + b64(json.dumps(obj, separators=(",", ":"))))
        again = parse_uri(encode_uri(n))
        self.assertEqual(again["host"], "10.1.2.3")
        self.assertEqual(again["uuid"], n["uuid"])
        self.assertEqual(again["port"], 8443)
        self.assertTrue(again["tls"])
        self.assertEqual(again["name"], "RT-VM")


class VlessTests(unittest.TestCase):
    def test_tls_ws(self):
        uri = (
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@vless.example.com:443"
            "?type=ws&security=tls&sni=vless.example.com&path=%2Fws&host=vless.example.com"
            "&encryption=none#VLESS-WS"
        )
        n = parse_uri(uri)
        self.assertEqual(n["type"], "vless")
        self.assertEqual(n["uuid"], "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        self.assertEqual(n["host"], "vless.example.com")
        self.assertEqual(n["port"], 443)
        self.assertEqual(n["network"], "ws")
        self.assertTrue(n["tls"])
        self.assertEqual(n["path"], "/ws")
        self.assertEqual(n["sni"], "vless.example.com")
        self.assertEqual(n["name"], "VLESS-WS")

    def test_reality_flow(self):
        uri = (
            "vless://11111111-2222-3333-4444-555555555555@203.0.113.50:443"
            "?security=reality&type=tcp&flow=xtls-rprx-vision&sni=www.microsoft.com&fp=chrome#vision"
        )
        n = parse_uri(uri)
        self.assertEqual(n["security"], "reality")
        self.assertEqual(n["flow"], "xtls-rprx-vision")
        self.assertTrue(n["tls"])

    def test_vless_roundtrip(self):
        uri = "vless://abcdabcd-abcd-abcd-abcd-abcdabcdabcd@192.0.2.9:443?type=tcp&security=tls&sni=x.example&encryption=none#VL"
        n = parse_uri(uri)
        again = parse_uri(encode_uri(n))
        self.assertEqual(again["uuid"], n["uuid"])
        self.assertEqual(again["host"], n["host"])
        self.assertEqual(again["sni"], "x.example")
        self.assertEqual(again["name"], "VL")


class TrojanTests(unittest.TestCase):
    def test_basic(self):
        uri = "trojan://Tr0jan-Pass@trojan.example.org:443?sni=trojan.example.org&allowInsecure=0#TJ"
        n = parse_uri(uri)
        self.assertEqual(n["type"], "trojan")
        self.assertEqual(n["password"], "Tr0jan-Pass")
        self.assertEqual(n["host"], "trojan.example.org")
        self.assertEqual(n["port"], 443)
        self.assertEqual(n["sni"], "trojan.example.org")
        self.assertTrue(n["tls"])
        self.assertEqual(n["name"], "TJ")

    def test_ws_insecure(self):
        uri = "trojan://pw%40x@10.0.0.8:8443?type=ws&path=/tj&host=cdn.example&allowInsecure=1#wstj"
        n = parse_uri(uri)
        self.assertEqual(n["password"], "pw@x")
        self.assertTrue(n["allowInsecure"])
        self.assertEqual(n["network"], "ws")
        self.assertEqual(n["path"], "/tj")

    def test_trojan_roundtrip(self):
        n = parse_uri("trojan://secret@203.0.113.20:443?sni=a.example#T")
        again = parse_uri(encode_uri(n))
        self.assertEqual(again["password"], "secret")
        self.assertEqual(again["host"], "203.0.113.20")
        self.assertEqual(again["sni"], "a.example")


class Hysteria2Tests(unittest.TestCase):
    def test_hy2_alias(self):
        uri = "hy2://auth-token@hy.example.net:443?insecure=1&sni=hy.example.net#HY"
        n = parse_uri(uri)
        self.assertEqual(n["type"], "hysteria2")
        self.assertEqual(n["password"], "auth-token")
        self.assertTrue(n["allowInsecure"])
        self.assertEqual(n["sni"], "hy.example.net")
        self.assertEqual(n["name"], "HY")

    def test_full_hysteria2(self):
        uri = (
            "hysteria2://p%2Fw@203.0.113.40:8443"
            "?sni=hy2.example&obfs=salamander&obfs-password=obfspw#full"
        )
        n = parse_uri(uri)
        self.assertEqual(n["password"], "p/w")
        self.assertEqual(n["obfs"], "salamander")
        self.assertEqual(n["obfsPassword"], "obfspw")
        self.assertEqual(n["port"], 8443)

    def test_hy2_roundtrip(self):
        n = parse_uri("hysteria2://tok@192.0.2.4:443?sni=z.example#H")
        again = parse_uri(encode_uri(n))
        self.assertEqual(again["type"], "hysteria2")
        self.assertEqual(again["password"], "tok")
        self.assertEqual(again["sni"], "z.example")


class SocksHttpTests(unittest.TestCase):
    def test_socks5(self):
        n = parse_uri("socks5://user:pass@10.0.0.9:1080#s5")
        self.assertEqual(n["type"], "socks")
        self.assertEqual(n["username"], "user")
        self.assertEqual(n["password"], "pass")
        self.assertEqual(n["port"], 1080)

    def test_socks_roundtrip(self):
        n = parse_uri("socks://alice:secret@192.0.2.10:1080#S")
        again = parse_uri(encode_uri(n))
        self.assertEqual(again["username"], "alice")
        self.assertEqual(again["password"], "secret")

    def test_http_proxy(self):
        n = parse_uri("http://u:p@proxy.example:8080#hp")
        self.assertEqual(n["type"], "http")
        self.assertEqual(n["host"], "proxy.example")
        self.assertEqual(n["port"], 8080)
        self.assertFalse(n["tls"])

    def test_https_proxy(self):
        n = parse_uri("https://u:p@proxy.example:8443#hps")
        self.assertTrue(n["tls"])
        again = parse_uri(encode_uri(n))
        self.assertTrue(again["tls"])
        self.assertEqual(again["username"], "u")


class ClashTests(unittest.TestCase):
    def test_block_style(self):
        yaml_text = Path(HERE, "samples", "clash.yaml").read_text(encoding="utf-8")
        nodes = parse_clash_yaml(yaml_text, group="clash-g")
        types = {n["name"]: n for n in nodes}
        self.assertIn("ss-node", types)
        self.assertEqual(types["ss-node"]["type"], "ss")
        self.assertEqual(types["ss-node"]["method"], "aes-256-gcm")
        self.assertEqual(types["ss-node"]["password"], "sspass")
        self.assertEqual(types["vmess-node"]["type"], "vmess")
        self.assertEqual(types["vmess-node"]["uuid"], "550e8400-e29b-41d4-a716-446655440000")
        self.assertTrue(types["vmess-node"]["tls"])
        self.assertEqual(types["trojan-node"]["type"], "trojan")
        self.assertEqual(types["trojan-node"]["password"], "tjpass")
        self.assertEqual(types["vless-node"]["type"], "vless")
        self.assertEqual(types["vless-node"]["uuid"], "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        self.assertEqual(types["hy2-node"]["type"], "hysteria2")
        for n in nodes:
            self.assertEqual(n["group"], "clash-g")

    def test_flow_style(self):
        text = """
proxies:
  - { name: flow-ss, type: ss, server: 1.2.3.4, port: 8388, cipher: chacha20-ietf-poly1305, password: xyz }
"""
        nodes = parse_clash_yaml(text)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["method"], "chacha20-ietf-poly1305")
        self.assertEqual(nodes[0]["password"], "xyz")


class SubscriptionTests(unittest.TestCase):
    def test_base64_uri_list(self):
        lines = "\n".join(
            [
                "ss://aes-256-gcm:a@1.1.1.1:1#A",
                "trojan://pw@2.2.2.2:443?sni=x#B",
            ]
        )
        blob = b64(lines)
        nodes = parse_subscription_body(blob, group="sub1")
        self.assertEqual(len(nodes), 2)
        self.assertEqual(nodes[0]["type"], "ss")
        self.assertEqual(nodes[1]["type"], "trojan")
        self.assertEqual(nodes[0]["group"], "sub1")

    def test_plain_uri_list(self):
        text = "ss://aes-256-gcm:a@1.1.1.1:1#A\nvless://u@3.3.3.3:443?security=tls&encryption=none#C\n"
        nodes = parse_subscription_body(text)
        self.assertEqual(len(nodes), 2)

    def test_sip008(self):
        data = {
            "version": 1,
            "servers": [
                {
                    "id": "1",
                    "remarks": "sip-ss",
                    "server": "198.51.100.2",
                    "server_port": 8388,
                    "password": "k",
                    "method": "chacha20-ietf-poly1305",
                }
            ],
        }
        nodes = parse_sip008(data)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["name"], "sip-ss")
        self.assertEqual(nodes[0]["method"], "chacha20-ietf-poly1305")
        nodes2 = parse_subscription_body(json.dumps(data))
        self.assertEqual(len(nodes2), 1)

    def test_clash_as_subscription(self):
        yaml_text = Path(HERE, "samples", "clash.yaml").read_text(encoding="utf-8")
        nodes = parse_subscription_body(yaml_text, group="Y")
        self.assertGreaterEqual(len(nodes), 4)


class SampleFileTests(unittest.TestCase):
    def test_nodes_txt(self):
        text = Path(HERE, "samples", "nodes.txt").read_text(encoding="utf-8")
        from parser_lib import parse_many_uris

        nodes = parse_many_uris(text)
        schemes = {n["type"] for n in nodes}
        self.assertGreaterEqual(len(nodes), 7)
        for need in ("ss", "vmess", "vless", "trojan", "hysteria2", "socks", "http"):
            self.assertIn(need, schemes, f"missing {need}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
