# Security policy

## Reporting a problem

Open a private security advisory on the project's GitHub repository. Do not
open a public issue for anything that could be exploited.

We acknowledge reports within two working days.

## Incident response

1. Set `AGENT_DISABLED=1` in the deployment environment. The assistant refuses
   every request while the flag is set.
2. Export the `audit` log for the affected window; it records every tool call
   by name and argument keys.
3. Rotate the model provider credentials.
4. Write up the timeline and the fix in the advisory before re-enabling.
