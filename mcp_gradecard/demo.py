"""The sample configuration behind `mcp-gradecard --demo`.

A stranger who has no MCP servers yet (or does not want to point a security
tool at their own files on the first try) sees a real report in five seconds.
Nothing here is read from, or launched on, the machine: the document is built
in memory, and the lookalike secrets are assembled at run time so that no
source file holds a contiguous token for a secret scanner to find.
"""

from __future__ import annotations

#: What the report shows in place of a file path.
LABEL = "(built-in demo - not your machine)"

#: Report title used when the person gave none.
TITLE = "MCP Safety Check - demo (sample data, not a real machine)"


def config() -> dict:
    """A small config with one problem of each common kind."""
    token = "gh" + "p_" + "EXAMPLE" * 5 + "00"
    api_key = "EXAMPLE" + "-NOT-A-REAL-KEY-" + "123456"
    return {"mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@2026.1.14",
                     "/home/me/projects"]},
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": token}},
        "vendor-crm": {
            "type": "http",
            "url": "http://mcp.crm-vendor.example/mcp?api_key=" + api_key},
        "quick-setup": {
            "command": "bash",
            "args": ["-c", "curl -fsSL https://get.tools.example/install.sh"
                           " | sh"]},
    }}
