#!/usr/bin/env python3

"""
Generador de tráfico para api-auth.

Ejemplos:
  python tests/generate_api_traffic.py
  python tests/generate_api_traffic.py --rounds 20 --sleep 0.2
  python tests/generate_api_traffic.py --base-url http://localhost:8000 --include-failures
  python tests/generate_api_traffic.py --only root docs metrics
  python tests/generate_api_traffic.py --list-endpoints

Ayuda:
  python tests/generate_api_traffic.py --help
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from collections import Counter
from typing import Any

import requests


DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_TIMEOUT = 10.0


def build_endpoints(base_url: str) -> list[dict[str, Any]]:
    return [
        {"name": "root", "method": "GET", "url": f"{base_url}/", "kind": "success"},
        {"name": "docs", "method": "GET", "url": f"{base_url}/docs", "kind": "success"},
        {"name": "openapi", "method": "GET", "url": f"{base_url}/openapi.json", "kind": "success"},
        {"name": "metrics", "method": "GET", "url": f"{base_url}/metrics", "kind": "success"},
        {
            "name": "user_ok",
            "method": "GET",
            "url": f"{base_url}/user",
            "params": {"username": "admin"},
            "kind": "success",
        },
        {
            "name": "user_sqli",
            "method": "GET",
            "url": f"{base_url}/user",
            "params": {"username": "admin' OR '1'='1"},
            "kind": "failure",
        },
        {
            "name": "hash",
            "method": "GET",
            "url": f"{base_url}/hash",
            "params": {"password": "test123"},
            "kind": "success",
        },
        {
            "name": "read_ok",
            "method": "GET",
            "url": f"{base_url}/read",
            "params": {"path": "/etc/hosts"},
            "kind": "success",
        },
        {
            "name": "read_fail",
            "method": "GET",
            "url": f"{base_url}/read",
            "params": {"path": "/no/existe/archivo.txt"},
            "kind": "failure",
        },
        {
            "name": "exec_ok",
            "method": "GET",
            "url": f"{base_url}/exec",
            "params": {"host": "127.0.0.1"},
            "kind": "success",
        },
        {
            "name": "exec_injection",
            "method": "GET",
            "url": f"{base_url}/exec",
            "params": {"host": "127.0.0.1; ls"},
            "kind": "failure",
        },
        {
            "name": "fetch_ok",
            "method": "GET",
            "url": f"{base_url}/fetch",
            "params": {"url": "https://example.com"},
            "kind": "success",
        },
        {
            "name": "fetch_fail",
            "method": "GET",
            "url": f"{base_url}/fetch",
            "params": {"url": "http://no-valido.local"},
            "kind": "failure",
        },
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Genera tráfico HTTP contra api-auth para poblar métricas de Prometheus/Grafana."
    )

    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"URL base de la API. Por defecto: {DEFAULT_BASE_URL}",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=10,
        help="Cantidad de rondas completas sobre los endpoints seleccionados. Por defecto: 10",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.5,
        help="Tiempo de espera en segundos entre llamadas. Por defecto: 0.5",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout por request en segundos. Por defecto: {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--include-failures",
        action="store_true",
        help="Incluye endpoints que tienden a provocar errores o respuestas fallidas.",
    )
    parser.add_argument(
        "--only",
        nargs="+",
        help="Lista de nombres de endpoints a ejecutar. Ejemplo: --only root docs metrics",
    )
    parser.add_argument(
        "--random-order",
        action="store_true",
        help="Mezcla el orden de los endpoints en cada ronda.",
    )
    parser.add_argument(
        "--list-endpoints",
        action="store_true",
        help="Muestra los endpoints disponibles y sale.",
    )
    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Detiene la ejecución si ocurre un error de conexión.",
    )

    return parser.parse_args()


def filter_endpoints(
    endpoints: list[dict[str, Any]],
    include_failures: bool,
    only: list[str] | None,
) -> list[dict[str, Any]]:
    selected = endpoints

    if not include_failures:
        selected = [ep for ep in selected if ep["kind"] == "success"]

    if only:
        wanted = set(only)
        selected = [ep for ep in selected if ep["name"] in wanted]

    return selected


def list_endpoints(endpoints: list[dict[str, Any]]) -> None:
    print("Endpoints disponibles:\n")
    for ep in endpoints:
        params = ep.get("params", {})
        print(
            f"- {ep['name']:<15} | {ep['method']:<4} | {ep['url']} | "
            f"tipo={ep['kind']} | params={params}"
        )


def call_endpoint(endpoint: dict[str, Any], timeout: float) -> tuple[int, float, str]:
    method = endpoint.get("method", "GET").upper()
    url = endpoint["url"]
    params = endpoint.get("params")
    json_body = endpoint.get("json")

    start = time.perf_counter()
    try:
        response = requests.request(
            method=method,
            url=url,
            params=params,
            json=json_body,
            timeout=timeout,
        )
        elapsed = time.perf_counter() - start
        return response.status_code, elapsed, ""
    except requests.RequestException as exc:
        elapsed = time.perf_counter() - start
        return 0, elapsed, str(exc)


def main() -> int:
    args = parse_args()
    all_endpoints = build_endpoints(args.base_url)

    if args.list_endpoints:
        list_endpoints(all_endpoints)
        return 0

    endpoints = filter_endpoints(
        endpoints=all_endpoints,
        include_failures=args.include_failures,
        only=args.only,
    )

    if not endpoints:
        print("No quedaron endpoints seleccionados. Revisa --only o --include-failures.")
        return 1

    print(f"Generando tráfico hacia: {args.base_url}")
    print(f"Rondas: {args.rounds}")
    print(f"Sleep entre llamadas: {args.sleep}s")
    print(f"Timeout por request: {args.timeout}s")
    print(f"Include failures: {args.include_failures}")
    print(f"Orden aleatorio: {args.random_order}")
    print("-" * 80)

    status_counter: Counter[str] = Counter()
    endpoint_counter: Counter[str] = Counter()
    total_calls = 0
    total_time = 0.0

    for round_num in range(1, args.rounds + 1):
        print(f"\nRonda {round_num}/{args.rounds}")

        round_endpoints = endpoints.copy()
        if args.random_order:
            random.shuffle(round_endpoints)

        for endpoint in round_endpoints:
            status_code, elapsed, error = call_endpoint(endpoint, timeout=args.timeout)
            total_calls += 1
            total_time += elapsed
            endpoint_counter[endpoint["name"]] += 1

            if status_code == 0:
                status_counter["REQUEST_ERROR"] += 1
                print(
                    f"[{endpoint['name']:<15}] ERROR         | {elapsed:>7.3f}s | {error}"
                )
                if args.stop_on_error:
                    print("\nDetenido por --stop-on-error")
                    return 2
            else:
                status_counter[str(status_code)] += 1
                print(
                    f"[{endpoint['name']:<15}] HTTP {status_code:<5} | {elapsed:>7.3f}s"
                )

            time.sleep(args.sleep)

    avg_time = total_time / total_calls if total_calls else 0.0

    print("\n" + "=" * 80)
    print("RESUMEN")
    print("=" * 80)
    print(f"Total de llamadas: {total_calls}")
    print(f"Tiempo promedio:   {avg_time:.3f}s")

    print("\nCódigos de respuesta:")
    for code, count in sorted(status_counter.items()):
        print(f"  {code}: {count}")

    print("\nLlamadas por endpoint:")
    for name, count in sorted(endpoint_counter.items()):
        print(f"  {name}: {count}")

    print("\nSiguiente verificación:")
    print("  - http://localhost:9090/targets")
    print("  - http://localhost:9090")
    print("  - http://localhost:3000")

    return 0

if __name__ == "__main__":
    sys.exit(main())