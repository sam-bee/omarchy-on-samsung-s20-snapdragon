#!/usr/bin/env python3
"""Static checks for the standalone startup dependency split."""
from pathlib import Path


PAYLOAD = Path(__file__).resolve().parents[1]
ROOTFS = PAYLOAD / "rootfs"


def read(relative: str) -> str:
    return (ROOTFS / relative).read_text(encoding="utf-8")


def unit_fields(relative: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    section = ""
    for line in read(relative).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section != "Unit" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"Requires", "Wants", "After", "Before"}:
            fields.setdefault(key, []).extend(value.split())
    return fields


def check_unit_graph() -> None:
    paths = {
        "r8q-hardware-prepare.service": "etc/systemd/system/r8q-hardware-prepare.service",
        "r8q-usb-gadget.service": "etc/systemd/system/r8q-usb-gadget.service",
        "r8q-usb-route.service": "etc/systemd/system/r8q-usb-route.service",
        "r8q-gpu.service": "etc/systemd/system/r8q-gpu.service",
        "r8q-touch.service": "etc/systemd/system/r8q-touch.service",
        "r8q-wifi.service": "etc/systemd/system/r8q-wifi.service",
        "r8q-battery.service": "etc/systemd/system/r8q-battery.service",
        "r8q-audio-start.service": "etc/systemd/system/r8q-audio-start.service",
        "r8q-desktop.service": "etc/systemd/system/r8q-desktop.service",
    }
    graph: dict[str, set[str]] = {name: set() for name in paths}
    graph["network-pre.target"] = set()
    fields = {name: unit_fields(path) for name, path in paths.items()}
    for name, values in fields.items():
        for predecessor in values.get("After", []):
            graph.setdefault(predecessor, set()).add(name)
        for successor in values.get("Before", []):
            graph[name].add(successor)

    state: dict[str, int] = {}
    def visit(node: str) -> None:
        mark = state.get(node, 0)
        assert mark != 1, f"systemd ordering cycle includes {node}"
        if mark == 2:
            return
        state[node] = 1
        for child in graph.get(node, ()):
            visit(child)
        state[node] = 2
    for node in graph:
        visit(node)

    def required_closure(root: str) -> set[str]:
        result: set[str] = set()
        pending = list(fields[root].get("Requires", []))
        while pending:
            item = pending.pop()
            if item in result:
                continue
            result.add(item)
            pending.extend(fields.get(item, {}).get("Requires", []))
        return result

    desktop_requires = required_closure("r8q-desktop.service")
    assert {"r8q-hardware-prepare.service", "r8q-gpu.service",
            "r8q-touch.service", "r8q-battery.service"} <= desktop_requires
    assert "r8q-usb-route.service" not in desktop_requires
    assert fields["r8q-usb-route.service"]["Requires"] == ["r8q-hardware-prepare.service"]
    assert "r8q-hardware-prepare.service" in fields["r8q-usb-route.service"]["After"]
    assert "r8q-usb-gadget.service" not in fields["r8q-usb-route.service"].get("Wants", [])
    assert "r8q-usb-gadget.service" not in fields["r8q-usb-route.service"]["After"]
    assert "r8q-hardware-prepare.service" in fields["r8q-audio-start.service"]["Requires"]
    assert "r8q-battery.service" in fields["r8q-audio-start.service"]["Wants"]
    assert "r8q-hardware-prepare.service" in fields["r8q-usb-gadget.service"]["Requires"]


def main() -> int:
    check_unit_graph()
    prepare = read("etc/systemd/system/r8q-hardware-prepare.service")
    assert "Environment=R8Q_USB_ROUTE_OPTIONAL_NOHOST=1" in prepare
    assert "Before=network-pre.target" in prepare
    for unit in ("r8q-gpu.service", "r8q-touch.service", "r8q-wifi.service",
                 "r8q-battery.service", "r8q-audio-start.service",
                 "NetworkManager.service", "r8q-desktop.service"):
        assert unit in prepare

    battery = read("usr/local/sbin/r8q-battery-up.sh")
    assert "require_unit_active r8q-hardware-prepare.service" in battery
    assert "require_unit_active r8q-usb-route.service" not in battery
    assert "require_usb_configured" not in battery
    assert "current_usb_udc" not in battery

    for relative in (
        "etc/systemd/system/r8q-usb-route.service",
        "etc/systemd/system/r8q-gpu.service",
        "etc/systemd/system/r8q-touch.service",
        "etc/systemd/system/r8q-wifi.service",
        "etc/systemd/system/r8q-battery.service",
        "etc/systemd/system/NetworkManager.service.d/10-r8q-usb-route.conf",
    ):
        text = read(relative)
        assert "r8q-hardware-prepare.service" in text
        if relative != "etc/systemd/system/r8q-usb-route.service":
            assert "Requires=r8q-usb-route.service" not in text
    route = read("etc/systemd/system/r8q-usb-route.service")
    assert "ExecStart=/usr/local/sbin/r8q-usb-route-witness.sh" in route
    assert "ExecStart=/usr/local/sbin/r8q-usb-route-up.sh" not in route

    desktop = read("etc/systemd/system/r8q-desktop.service")
    assert "r8q-battery.service" in desktop and "r8q-hardware-prepare.service" in desktop
    assert "ExecStartPre=/usr/bin/systemctl is-active --quiet r8q-hardware-prepare.service" in desktop
    audio = read("etc/systemd/system/r8q-audio-start.service")
    assert "Requires=r8q-hardware-prepare.service" in audio
    assert "After=local-fs.target r8q-hardware-prepare.service" in audio
    assert "ExecStartPre=/usr/bin/systemctl is-active --quiet r8q-hardware-prepare.service" in audio
    assert "Wants=r8q-audio-start.service" in read("etc/systemd/system/r8q-desktop.service.d/20-audio.conf")

    builder = (PAYLOAD / "scripts/prepare-arch-rootfs.py").read_text(encoding="utf-8")
    assert "network-pre.target.wants/r8q-hardware-prepare.service" in builder
    links_body = builder.split("links = {", 1)[1].split("for relative", 1)[0]
    assert "multi-user.target.wants/r8q-usb-route.service" not in links_body
    assert "remove_managed_symlink" in builder
    assert "USB_ROUTE_WITNESS" in builder
    assert "usr/local/sbin/r8q-usb-route-witness.sh" in builder
    print("PASS: standalone service ordering, optional gate, battery UDC split, and legacy route disablement")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
