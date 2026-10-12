from __future__ import annotations

from typing import Any

from azure_risk_tool.analysis.common import finding, normalized_id, properties


PUBLIC_SOURCES = {"*", "0.0.0.0/0", "internet", "any"}
MANAGEMENT_PORTS = {"22": "SSH", "3389": "RDP", "5985": "WinRM", "5986": "WinRM HTTPS"}


def analyze(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for nsg in inventory.get("network_security_groups", []):
        for rule in properties(nsg).get("securityRules", []):
            rule_props = properties(rule)
            if str(rule_props.get("direction", "")).lower() != "inbound":
                continue
            if str(rule_props.get("access", "")).lower() != "allow":
                continue
            sources = _values(rule_props, "sourceAddressPrefix", "sourceAddressPrefixes")
            ports = _values(rule_props, "destinationPortRange", "destinationPortRanges")
            if not any(source.lower() in PUBLIC_SOURCES for source in sources):
                continue
            exposed = _management_ports(ports)
            if exposed:
                resource = dict(nsg)
                resource["type"] = "Microsoft.Network/networkSecurityGroups"
                findings.append(
                    finding(
                        "AZ-NET-001",
                        "Management port exposed to the Internet",
                        "Network",
                        "High",
                        resource,
                        "An inbound NSG rule permits Internet access to a remote administration service.",
                        {
                            "rule": rule.get("name"),
                            "sources": sources,
                            "ports": ports,
                            "services": exposed,
                        },
                        "Restrict the rule to trusted source addresses or use Azure Bastion, VPN or a private management network.",
                        internet_exposure=10,
                        exploitability=8,
                    )
                )
    public_ids = {normalized_id(item.get("id")) for item in inventory.get("public_ip_addresses", [])}
    for nic in inventory.get("network_interfaces", []):
        for configuration in properties(nic).get("ipConfigurations", []):
            public_ip = properties(configuration).get("publicIPAddress", {})
            public_id = normalized_id(public_ip.get("id") if isinstance(public_ip, dict) else None)
            if public_id and public_id in public_ids:
                resource = dict(nic)
                resource["type"] = "Microsoft.Network/networkInterfaces"
                findings.append(
                    finding(
                        "AZ-NET-002",
                        "Network interface has a public IP address",
                        "Network",
                        "Medium",
                        resource,
                        "The network interface is directly reachable through a public IP address.",
                        {"public_ip_id": public_id},
                        "Confirm that public exposure is required and protect the interface with restrictive NSG rules.",
                        internet_exposure=6,
                        exploitability=3,
                    )
                )
    return findings


def _values(props: dict[str, Any], single: str, multiple: str) -> list[str]:
    values = props.get(multiple)
    if isinstance(values, list):
        return [str(value) for value in values]
    value = props.get(single)
    return [str(value)] if value is not None else []


def _management_ports(ports: list[str]) -> list[str]:
    if "*" in ports:
        return list(MANAGEMENT_PORTS.values())
    result: list[str] = []
    for port in ports:
        if port in MANAGEMENT_PORTS:
            result.append(MANAGEMENT_PORTS[port])
            continue
        if "-" in port:
            try:
                start, end = [int(value) for value in port.split("-", 1)]
            except ValueError:
                continue
            for number, service in MANAGEMENT_PORTS.items():
                if start <= int(number) <= end:
                    result.append(service)
    return sorted(set(result))
