"""Path explanation skeleton."""

from adpath.models.path import AttackPath


class PathExplainer:
    """Explain why a path exists and what information is missing."""

    def explain(self, path: AttackPath) -> str:
        """Return a human-readable path explanation."""
        if not path.nodes:
            return f"{path.path_type}: {path.start} -> {path.target}"
        lines = [f"{path.path_type}: {path.nodes[0].name} -> {path.nodes[-1].name}"]
        for index, edge in enumerate(path.edges):
            source = path.nodes[index].name if index < len(path.nodes) else edge.source
            target = path.nodes[index + 1].name if index + 1 < len(path.nodes) else edge.target
            lines.append(f"{source} has {edge.relationship} to {target}.")
            if edge.relationship == "GenericWrite":
                lines.append(f"  -> Candidate object-specific control over {target}; verify writable attributes.")
            elif edge.relationship == "MemberOf":
                lines.append(f"  -> Membership may inherit privileges from {target}; verify group tier.")
            elif edge.relationship == "AdminTo":
                lines.append(f"  -> Local admin on {target}; domain impact depends on sessions or credentials.")
            elif edge.relationship in {"WriteDACL", "WriteOwner"}:
                lines.append(f"  -> Enabling permission on {target}; follow-on ACL change still needs confirmation.")
        if path.missing_information:
            lines.append("Missing information:")
            for item in path.missing_information:
                lines.append(f"- {item.question} ({item.suggested_source}, {item.importance.name.lower()})")
        return "\n".join(lines)
