// Types for the parts of scripts/agent.mjs the tests import (the script itself stays plain JS, no build step).
export function headcountArgs(args: string[]): { after?: number; repo?: string };
