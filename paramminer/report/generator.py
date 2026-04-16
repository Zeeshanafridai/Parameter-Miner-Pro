"""Report generator for param miner findings."""
import json, datetime

def generate(results: dict, prefix: str = "paramminer_report") -> dict:
    now   = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    jpath = f"{prefix}_{now}.json"
    mpath = f"{prefix}_{now}.md"

    with open(jpath, "w") as f:
        json.dump(results, f, indent=2, default=str)

    params  = results.get("found_params", [])
    headers = results.get("found_headers", [])
    lines   = []

    lines.append("# Parameter Miner Pro — Findings\n")
    lines.append(f"**Target:** `{results.get('url','')}`  ")
    lines.append(f"**Date:** {results.get('start_time','')}  ")
    lines.append(f"**Found:** {len(params)} params, {len(headers)} headers  \n")
    lines.append("---\n")

    if params:
        lines.append("## Hidden Parameters\n")
        for p in params:
            lines.append(f"### `{p['param']}`\n")
            lines.append(f"- **Reflected:** {p.get('reflected', False)}")
            diff = p.get("diff", {})
            lines.append(f"- **Size diff:** {diff.get('size_diff', 0):+d} bytes")
            lines.append(f"- **Confidence:** {diff.get('confidence', 0)}%")
            behs = p.get("behaviors", [])
            if behs:
                lines.append(f"- **Behaviors:** {', '.join(b['behavior'] for b in behs)}")
            lines.append("")

    if headers:
        lines.append("## Interesting Headers\n")
        for h in headers:
            lines.append(f"- **{h['name']}** = `{h['value_tested']}` "
                         f"({h.get('category','')}) — {h.get('detail','')}")
        lines.append("")

    lines.append("## Remediation\n")
    lines.append("- Remove or disable undocumented parameters in production")
    lines.append("- Do not change behavior based on internal/debug params for unauthenticated users")
    lines.append("- Validate all incoming parameter names against an allowlist")
    lines.append("- Review cache-poisoning headers with your CDN/proxy team\n")

    with open(mpath, "w") as f:
        f.write("\n".join(lines))

    return {"json": jpath, "markdown": mpath}
