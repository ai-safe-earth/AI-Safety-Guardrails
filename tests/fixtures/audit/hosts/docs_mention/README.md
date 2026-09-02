# Working with the coding agent

Run the agent from the repository root so it picks up the project settings.

Never run it with `--dangerously-skip-permissions`. That flag turns off the
approval prompt for every shell command, and the whole point of the prompt is
that a human reads the command before it runs. If you find yourself wanting
it, add a narrow entry to `permissions.allow` instead.
