from __future__ import annotations

import logging
import os
from flask import Flask, jsonify, render_template, request
from network_scanner import NetworkScanner, ScanError, validate_mac, validate_nickname


def create_app(scanner_service: NetworkScanner | None = None) -> Flask:
    app = Flask(__name__, template_folder="html")
    service = scanner_service or NetworkScanner(
        max_workers=int(os.getenv("NETSCAN_WORKERS", "64")),
        timeout=float(os.getenv("NETSCAN_TIMEOUT", ".8")),
        max_hosts=int(os.getenv("NETSCAN_MAX_HOSTS", "1024")),
    )
    app.config["SCANNER_SERVICE"] = service

    @app.get("/")
    def dashboard(): return render_template("home.html")

    @app.get("/api/health")
    def health(): return jsonify(status="ok", persistence=bool(service.store.client))

    @app.get("/api/interfaces")
    def interfaces(): return jsonify([item.to_dict() for item in service.interfaces()])

    @app.post("/api/scans")
    def scan():
        payload = request.get_json(silent=True)
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            raise ScanError("The request body must be a JSON object.")
        interface = str(payload.get("interface", "")).strip()
        if not interface:
            raise ScanError("The interface field is required.")
        details = payload.get("details", False)
        if not isinstance(details, bool):
            raise ScanError("The details field must be true or false.")
        devices, duration = service.scan(interface, details=details)
        return jsonify(interface=interface, devices=devices, count=len(devices),
                       duration_seconds=duration, details=details)

    @app.get("/api/nicknames")
    def nicknames(): return jsonify(service.store.all_nicknames())

    @app.put("/api/devices/<mac_address>/nickname")
    def nickname(mac_address: str):
        payload = request.get_json(silent=True) or {}
        mac = validate_mac(mac_address)
        name = validate_nickname(str(payload.get("nickname", "")))
        service.store.set_nickname(mac, name)
        return jsonify(mac_address=mac, nickname=name)

    @app.errorhandler(ScanError)
    def scan_error(error): return jsonify(error=str(error)), 400

    @app.errorhandler(404)
    def not_found(_error): return jsonify(error="Not found"), 404
    return app


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
scanner = create_app()

if __name__ == "__main__":
    scanner.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")))
