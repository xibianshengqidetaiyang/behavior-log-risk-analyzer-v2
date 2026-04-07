from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import pandas as pd

DOMAIN_RE = re.compile(r"访问域名\s*[:：]\s*([^\s]+)")
URL_RE = re.compile(r"URL地址\s*[:：]\s*([^\s]+)", re.IGNORECASE)
SRC_PORT_RE = re.compile(r"源端口\s*[:：]\s*(\d+)")
DST_PORT_RE = re.compile(r"服务端口\s*[:：]\s*(\d+)")
PROTO_RE = re.compile(r"协议\s*[:：]\s*([^\s]+)")
FILE_RE = re.compile(r"(?:文件名|下载文件|file)\s*[:：]\s*([^\s]+)", re.IGNORECASE)


def clean_text(value) -> str:
    if pd.isna(value):
        return ""
    return str(value).strip()


def normalize_ip(value) -> str:
    value = clean_text(value)
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value))
    except Exception:
        return value


def normalize_domain(value) -> str:
    value = clean_text(value).lower()
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        return urlparse(value).netloc.lower()
    return value.strip("/")


def normalize_url(value) -> str:
    value = clean_text(value)
    return value.strip()


def guess_domain_from_url(url: str) -> str:
    url = normalize_url(url)
    if not url:
        return ""
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def extract_filename_from_url(url: str) -> str:
    url = normalize_url(url)
    if not url:
        return ""
    try:
        path = urlparse(url).path.strip("/")
        if not path:
            return ""
        return path.split("/")[-1]
    except Exception:
        return ""


def extract_detail_fields(detail: str) -> dict:
    text = clean_text(detail)
    domain = DOMAIN_RE.search(text)
    url = URL_RE.search(text)
    src_port = SRC_PORT_RE.search(text)
    dst_port = DST_PORT_RE.search(text)
    proto = PROTO_RE.search(text)
    filename = FILE_RE.search(text)

    detail_url = normalize_url(url.group(1)) if url else ""
    detail_domain = normalize_domain(domain.group(1)) if domain else guess_domain_from_url(detail_url)

    return {
        "detail_domain": detail_domain,
        "detail_url": detail_url,
        "src_port": int(src_port.group(1)) if src_port else None,
        "dst_port": int(dst_port.group(1)) if dst_port else None,
        "protocol": clean_text(proto.group(1)).upper() if proto else "",
        "download_file": clean_text(filename.group(1)) if filename else extract_filename_from_url(detail_url),
    }


def is_public_ip(value: str) -> bool:
    value = clean_text(value)
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_global
    except Exception:
        return False
