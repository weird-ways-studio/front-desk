// Types for the parts of scripts/agent.mjs the tests import (the script itself stays plain JS, no build step).
export function headcountArgs(args: string[]): { after?: number; repo?: string };
export function driveReach(step: (body: string) => Promise<any>, demand: boolean, print?: (x: unknown) => void): Promise<any>;
export function reachAfterCollect(text: string): boolean;
