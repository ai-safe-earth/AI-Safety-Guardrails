# explain-doc

A Claude Code project skill that generates deep-dive HTML explainer documents
in `docs/explain/` — architecture/data-flow schemas, verified file:line code
walks, decisions with reasons, and actionable recommendations.

Install: copy this folder to `<your-project>/.claude/skills/explain-doc/`.
Invoke: `/explain-doc <topic>` (a phase, feature, subsystem, or branch).
The first doc generated becomes the depth/diagram exemplar for later ones.
