"""BloodHound JSON parser."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from zipfile import ZipFile

from adpath.models.edge import Edge
from adpath.models.node import Node, NodeType
from adpath.parsers.normalization import NormalizationResult

NODE_TYPES_BY_META = {
    "users": NodeType.USER,
    "groups": NodeType.GROUP,
    "computers": NodeType.COMPUTER,
    "ous": NodeType.OU,
    "gpos": NodeType.GPO,
    "domains": NodeType.DOMAIN,
    "containers": NodeType.CONTAINER,
    "certificatetemplates": NodeType.CERTIFICATE_TEMPLATE,
    "certificateauthorities": NodeType.CERTIFICATE_AUTHORITY,
    "cas": NodeType.CA,
}

ACL_RELATIONSHIPS = {
    "GenericAll": "GenericAll",
    "GenericWrite": "GenericWrite",
    "WriteDacl": "WriteDACL",
    "WriteDACL": "WriteDACL",
    "WriteOwner": "WriteOwner",
    "ForceChangePassword": "ForceChangePassword",
    "WriteSPN": "WriteSPN",
    "WriteSpn": "WriteSPN",
    "WriteSPNPrivilege": "WriteSPN",
    "CreateChild": "CreateChild",
    "CreateChildObjects": "CreateChild",
    "AddChild": "CreateChild",
}


class BloodHoundParser:
    """Parse BloodHound-style JSON exports into normalized nodes and edges."""

    source_tool = "bloodhound"

    def parse_path(self, path: Path | str) -> NormalizationResult:
        """Parse a JSON file, a directory of JSON files, or a BloodHound zip archive."""
        source = Path(path)
        result = NormalizationResult()
        if source.is_dir():
            for item in sorted(source.glob("*.json")):
                result.extend(self.parse_file_result(item))
            for item in sorted(source.glob("*.zip")):
                result.extend(self.parse_zip(item))
            return result
        if source.suffix.lower() == ".zip":
            return self.parse_zip(source)
        return self.parse_file_result(source)

    def parse_file(self, path: Path | str) -> tuple[list[Node], list[Edge]]:
        """Parse one JSON file and return normalized graph elements."""
        result = self.parse_file_result(path)
        return result.nodes, result.edges

    def parse_file_result(self, path: Path | str) -> NormalizationResult:
        """Parse one JSON file and return a normalization result with warnings."""
        file_path = Path(path)
        try:
            payload = json.loads(file_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            return NormalizationResult(warnings=[f"{file_path}: failed to parse JSON: {exc}"])
        return self.parse_payload(payload, source_name=file_path.name)

    def parse_zip(self, path: Path | str) -> NormalizationResult:
        """Parse JSON files inside a BloodHound zip archive."""
        archive_path = Path(path)
        result = NormalizationResult()
        try:
            with ZipFile(archive_path) as archive:
                names = sorted(name for name in archive.namelist() if name.lower().endswith(".json"))
                for name in names:
                    try:
                        payload = json.loads(archive.read(name).decode("utf-8-sig"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        result.warnings.append(f"{archive_path}:{name}: failed to parse JSON: {exc}")
                        continue
                    result.extend(self.parse_payload(payload, source_name=name))
        except OSError as exc:
            result.warnings.append(f"{archive_path}: failed to open zip archive: {exc}")
        return result

    def parse_records(self, records: list[dict[str, Any]]) -> tuple[list[Node], list[Edge]]:
        """Parse in-memory test records into normalized graph elements."""
        result = NormalizationResult()
        for record in records:
            result.extend(self.parse_record(record, meta_type=str(record.get("meta_type", "users"))))
        return result.nodes, result.edges

    def parse_payload(self, payload: dict[str, Any], source_name: str = "<memory>") -> NormalizationResult:
        """Parse a BloodHound JSON payload."""
        result = NormalizationResult()
        records = payload.get("data")
        meta = payload.get("meta") or {}
        meta_type = str(meta.get("type") or self._infer_type_from_name(source_name))
        if not isinstance(records, list):
            return NormalizationResult(warnings=[f"{source_name}: missing list field 'data'"])
        if meta_type not in NODE_TYPES_BY_META:
            result.warnings.append(f"{source_name}: unsupported BloodHound object type '{meta_type}'")
            return result
        for record in records:
            if not isinstance(record, dict):
                result.warnings.append(f"{source_name}: skipped non-object record")
                continue
            result.extend(self.parse_record(record, meta_type))
        return result

    def parse_record(self, record: dict[str, Any], meta_type: str) -> NormalizationResult:
        """Parse one BloodHound object record."""
        result = NormalizationResult()
        node_id = self._object_id(record)
        properties = self._properties(record)
        name = str(properties.get("name") or node_id)
        domain = self._normalize_domain(properties.get("domain"))
        if node_id is None:
            result.warnings.append(f"{meta_type}: skipped record without ObjectIdentifier")
            return result

        node = Node(
            id=node_id,
            name=name,
            type=self._semantic_node_type(meta_type, properties),
            domain=domain,
            properties=self._node_properties(record),
        )
        result.nodes.append(node)
        result.edges.extend(self._parse_aces(record, node.id))
        result.edges.extend(self._parse_primary_group(record, node.id))
        result.edges.extend(self._parse_contained_by(record, node.id))
        result.edges.extend(self._parse_sessions(record, node.id))
        result.edges.extend(self._parse_delegation(record, node.id))
        result.edges.extend(self._parse_password_readers(record, node.id))
        result.edges.extend(self._parse_certificate_relationships(record, node.id))
        result.edges.extend(self._parse_spn_marker(record, node.id))

        if meta_type == "groups":
            result.edges.extend(self._parse_members(record, node.id))
        if meta_type == "computers":
            result.edges.extend(self._parse_admin_to(record, node.id))
        if meta_type in {"ous", "domains", "containers"}:
            result.edges.extend(self._parse_contains(record, node.id))
        if meta_type == "ous":
            result.edges.extend(self._parse_gpo_links(record, node.id))
        return result

    def _semantic_node_type(self, meta_type: str, properties: dict[str, Any]) -> NodeType:
        node_type = NODE_TYPES_BY_META[meta_type]
        if meta_type == "users":
            sam = str(properties.get("samaccountname") or properties.get("name") or "")
            if self._truthy(properties.get("isdmsa")):
                return NodeType.DMSA
            if self._truthy(properties.get("isgmsa")):
                return NodeType.GMSA
            if properties.get("serviceprincipalnames") or self._truthy(properties.get("hasspn")):
                return NodeType.SERVICE_ACCOUNT
            if sam.endswith("$"):
                return NodeType.GMSA
        return node_type

    def _parse_members(self, record: dict[str, Any], group_id: str) -> list[Edge]:
        edges = []
        for member in record.get("Members") or []:
            member_id = self._nested_object_id(member)
            if member_id:
                edges.append(self._edge(member_id, group_id, "MemberOf", object_type=member.get("ObjectType")))
        return edges

    def _parse_aces(self, record: dict[str, Any], target_id: str) -> list[Edge]:
        edges = []
        for ace in record.get("Aces") or []:
            relationship = ACL_RELATIONSHIPS.get(str(ace.get("RightName") or ""))
            principal = self._normalize_id(ace.get("PrincipalSID"))
            if relationship and principal:
                edges.append(
                    self._edge(
                        principal,
                        target_id,
                        relationship,
                        inherited=bool(ace.get("IsInherited", False)),
                        principal_type=ace.get("PrincipalType"),
                    )
                )
        return edges

    def _parse_primary_group(self, record: dict[str, Any], node_id: str) -> list[Edge]:
        primary_group = self._normalize_id(record.get("PrimaryGroupSID"))
        if not primary_group:
            return []
        return [self._edge(node_id, primary_group, "MemberOf", primary=True)]

    def _parse_contained_by(self, record: dict[str, Any], child_id: str) -> list[Edge]:
        container = record.get("ContainedBy")
        if not isinstance(container, dict):
            return []
        container_id = self._nested_object_id(container)
        if not container_id:
            return []
        return [
            self._edge(
                container_id,
                child_id,
                "Contains",
                object_type=container.get("ObjectType"),
                source_field="ContainedBy",
            )
        ]

    def _parse_admin_to(self, record: dict[str, Any], computer_id: str) -> list[Edge]:
        edges = []
        local_admins = record.get("LocalAdmins") or {}
        for principal in local_admins.get("Results") or []:
            principal_id = self._nested_object_id(principal)
            if principal_id:
                edges.append(
                    self._edge(
                        principal_id,
                        computer_id,
                        "AdminTo",
                        object_type=principal.get("ObjectType"),
                    )
                )
        return edges

    def _parse_contains(self, record: dict[str, Any], container_id: str) -> list[Edge]:
        edges = []
        for child in record.get("ChildObjects") or []:
            child_id = self._nested_object_id(child)
            if child_id:
                edges.append(
                    self._edge(
                        container_id,
                        child_id,
                        "Contains",
                        object_type=child.get("ObjectType"),
                    )
                )
        return edges

    def _parse_gpo_links(self, record: dict[str, Any], ou_id: str) -> list[Edge]:
        edges = []
        for link in record.get("Links") or []:
            gpo_id = self._normalize_id(link.get("GUID"))
            if gpo_id:
                edges.append(self._edge(gpo_id, ou_id, "LinkedTo", enforced=bool(link.get("IsEnforced", False))))
        return edges

    def _parse_sessions(self, record: dict[str, Any], computer_id: str) -> list[Edge]:
        edges = []
        sessions = record.get("Sessions") or {}
        for session in sessions.get("Results") or []:
            principal_id = self._nested_object_id(session)
            if principal_id:
                edges.append(
                    self._edge(
                        principal_id,
                        computer_id,
                        "HasSession",
                        object_type=session.get("ObjectType"),
                    )
                )
        return edges

    def _parse_delegation(self, record: dict[str, Any], node_id: str) -> list[Edge]:
        edges = []
        for item in record.get("AllowedToAct") or record.get("AllowedToActOnBehalfOfOtherIdentity") or []:
            principal_id = self._nested_object_id(item)
            if principal_id:
                edges.append(self._edge(principal_id, node_id, "AllowedToAct", object_type=item.get("ObjectType")))
        for item in record.get("AllowedToDelegate") or []:
            target_id = self._nested_object_id(item) or self._normalize_id(item.get("ComputerSID") if isinstance(item, dict) else item)
            if target_id:
                edges.append(self._edge(node_id, target_id, "AllowedToDelegate", object_type=item.get("ObjectType") if isinstance(item, dict) else None))
            elif isinstance(item, dict):
                spn = item.get("ServicePrincipalName") or item.get("SPN")
                if spn:
                    edges.append(self._edge(node_id, node_id, "AllowedToDelegate", service_principal_name=spn))
        props = self._properties(record)
        if self._truthy(props.get("unconstraineddelegation")):
            edges.append(self._edge(node_id, node_id, "UnconstrainedDelegation"))
        return edges

    def _parse_password_readers(self, record: dict[str, Any], account_id: str) -> list[Edge]:
        edges = []
        for field, relationship in (
            ("GMSAReaders", "ReadGMSAPassword"),
            ("DMSAReaders", "ReadDMSAPassword"),
        ):
            readers = record.get(field) or {}
            if isinstance(readers, dict):
                readers = readers.get("Results") or []
            for reader in readers or []:
                reader_id = self._nested_object_id(reader)
                if reader_id:
                    edges.append(self._edge(reader_id, account_id, relationship, object_type=reader.get("ObjectType")))
        return edges

    def _parse_certificate_relationships(self, record: dict[str, Any], node_id: str) -> list[Edge]:
        edges = []
        relation_fields = (
            ("Enroll", "Enroll"),
            ("AutoEnroll", "AutoEnroll"),
            ("ManageCA", "ManageCA"),
            ("ManageCertificates", "ManageCertificates"),
            ("TemplateControllers", "TemplateControl"),
        )
        for field, relationship in relation_fields:
            principals = record.get(field) or {}
            if isinstance(principals, dict):
                principals = principals.get("Results") or []
            for principal in principals or []:
                principal_id = self._nested_object_id(principal)
                if principal_id:
                    edges.append(self._edge(principal_id, node_id, relationship, object_type=principal.get("ObjectType")))
        return edges

    def _parse_spn_marker(self, record: dict[str, Any], node_id: str) -> list[Edge]:
        props = self._properties(record)
        spns = props.get("serviceprincipalnames") or props.get("ServicePrincipalNames")
        if not spns and not self._truthy(props.get("hasspn")):
            return []
        return [self._edge(node_id, node_id, "HasSPN", service_principal_names=spns or [])]

    def _edge(self, source: str, target: str, relationship: str, **properties: Any) -> Edge:
        return Edge(
            source=source,
            target=target,
            relationship=relationship,
            properties={key: value for key, value in properties.items() if value is not None},
            source_tool=self.source_tool,
        )

    def _node_properties(self, record: dict[str, Any]) -> dict[str, Any]:
        properties = self._properties(record).copy()
        for key in ("IsDeleted", "IsACLProtected", "Status"):
            if key in record:
                properties[key] = record[key]
        return properties

    def _properties(self, record: dict[str, Any]) -> dict[str, Any]:
        properties = record.get("Properties")
        return properties if isinstance(properties, dict) else {}

    def _object_id(self, record: dict[str, Any]) -> str | None:
        return self._normalize_id(record.get("ObjectIdentifier"))

    def _nested_object_id(self, record: dict[str, Any]) -> str | None:
        return self._normalize_id(record.get("ObjectIdentifier")) if isinstance(record, dict) else None

    def _normalize_id(self, value: Any) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized.upper() if normalized else None

    def _normalize_domain(self, value: Any) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized.upper() if normalized else None

    def _infer_type_from_name(self, source_name: str) -> str:
        name = source_name.lower()
        for meta_type in NODE_TYPES_BY_META:
            if meta_type in name:
                return meta_type
        return "unknown"

    def _truthy(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int | float):
            return value != 0
        if isinstance(value, str):
            return value.strip().casefold() in {"true", "1", "yes", "enabled"}
        return bool(value)
