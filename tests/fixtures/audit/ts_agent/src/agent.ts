// src/agent.ts
// Ask the model for a shell command, run it, and show the reply in the page.

import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";
import { exec } from "child_process";

export async function runTask(task: string, element: HTMLElement): Promise<string> {
  const result = await generateText({
    model: openai("gpt-4o"),
    system: "You turn a task description into a single shell command. Reply with the command only.",
    prompt: `Task: ${task}`,
  });
  const reply = result.text;

  exec(reply, (error, stdout, stderr) => {
    if (error) {
      console.error(stderr);
      return;
    }
    console.log(stdout);
  });

  element.innerHTML = reply;
  return reply;
}
