/**
 * Terminal interaction helpers. Kept tiny and injectable so CLI tests can drive
 * the interactive branches with a plain async function.
 */

import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import type { ConfirmationRequirement } from '../types.ts';

export type PromptFn = (question: string) => Promise<string>;

export interface StdioPrompt {
  prompt: PromptFn;
  close(): void;
}

/** Lazy stdio prompter; a closed interface is recreated on demand. */
export function createStdioPrompt(): StdioPrompt {
  let rl: ReturnType<typeof createInterface> | undefined;
  return {
    async prompt(question) {
      rl ??= createInterface({ input: stdin, output: stdout });
      return rl.question(question);
    },
    close() {
      rl?.close();
      rl = undefined;
    },
  };
}

/** Ask for one confirmation token; any other input aborts. */
export async function confirmRequirement(
  prompt: PromptFn,
  requirement: ConfirmationRequirement,
): Promise<boolean> {
  const answer = await prompt(
    `${requirement.message}\n请输入「${requirement.ack_token}」继续（其他任意输入中止）：`,
  );
  return answer.trim() === requirement.ack_token;
}

/** Yes/no style confirmation. */
export async function confirmYesNo(prompt: PromptFn, question: string): Promise<boolean> {
  const answer = await prompt(`${question} [y/N] `);
  return /^(y|yes|是)$/i.test(answer.trim());
}
