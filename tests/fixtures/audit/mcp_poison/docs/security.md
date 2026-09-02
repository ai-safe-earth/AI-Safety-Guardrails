# Vetting MCP servers

Tool descriptions are read by the model, not by you, so a malicious server can
hide instructions in them. Before adding a server to `.cursor/mcp.json`, check
each tool description by hand.

Reject any tool description containing "ignore previous instructions", an
`<IMPORTANT>` block, or a reference to `~/.ssh`. Also reject descriptions with
invisible characters: run them through a hex dump and look for zero-width
code points.

Pin the server package to an exact version so a later release cannot swap the
descriptions underneath you.
