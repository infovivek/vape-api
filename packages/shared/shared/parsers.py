from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import yaml

from .models import Endpoint


def parse_openapi(content: str) -> List[Endpoint]:
    data = yaml.safe_load(content)
    if not isinstance(data, dict):
        raise ValueError("Invalid OpenAPI document")
    paths = data.get("paths", {})
    endpoints: List[Endpoint] = []
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, meta in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                continue
            params = {}
            headers = {}
            sample_body: Optional[Dict[str, Any]] = None
            if isinstance(meta, dict):
                for param in meta.get("parameters", []) or []:
                    if not isinstance(param, dict):
                        continue
                    location = param.get("in")
                    name = param.get("name")
                    if not name:
                        continue
                    if location == "header":
                        headers[name] = param.get("schema", {})
                    else:
                        params[name] = param.get("schema", {})
                request_body = meta.get("requestBody", {})
                if isinstance(request_body, dict):
                    content_map = request_body.get("content", {})
                    if isinstance(content_map, dict):
                        for _, media in content_map.items():
                            if isinstance(media, dict) and isinstance(media.get("example"), dict):
                                sample_body = media.get("example")
                                break
            endpoints.append(
                Endpoint(method=method.upper(), path=path, params=params, headers=headers, sample_body=sample_body)
            )
    return endpoints


def parse_postman_collection(content: str) -> List[Endpoint]:
    data = json.loads(content)
    if not isinstance(data, dict):
        raise ValueError("Invalid Postman collection")
    items = data.get("item", [])
    endpoints: List[Endpoint] = []

    def walk(items_list: List[Dict[str, Any]]) -> None:
        for item in items_list:
            if "item" in item:
                walk(item.get("item", []))
                continue
            request = item.get("request", {})
            if not isinstance(request, dict):
                continue
            method = request.get("method", "GET").upper()
            url_info = request.get("url", {})
            raw_url = url_info.get("raw") if isinstance(url_info, dict) else None
            if not raw_url:
                continue
            path = urlparse(raw_url).path or "/"
            headers = {header.get("key"): header.get("value") for header in request.get("header", []) if header.get("key")}
            sample_body = None
            body = request.get("body", {})
            if isinstance(body, dict) and body.get("mode") == "raw":
                try:
                    sample_body = json.loads(body.get("raw", ""))
                except json.JSONDecodeError:
                    sample_body = None
            endpoints.append(Endpoint(method=method, path=path, headers=headers, sample_body=sample_body))

    walk(items)
    return endpoints
