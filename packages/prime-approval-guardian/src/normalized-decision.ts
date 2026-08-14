import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import {
	guardianInputIdentity,
	type NormalizedGuardianAction,
} from "./shared-decision.ts";

const MAX_CELL_CHARS = 64_000;

export type {
	GuardianAssessment,
	GuardianDecisionAudit,
	GuardianDecisionServices,
	GuardianReviewResult,
	NormalizedGuardianAction,
	NormalizedGuardianDecision,
} from "./shared-decision.ts";
export {
	decideGuardianAction,
	guardianInputIdentity,
} from "./shared-decision.ts";

export function normalizePrimeIpythonAction(
	input: unknown,
	cwd: string,
): NormalizedGuardianAction | undefined {
	if (!isPlainCodeInput(input)) return;
	const code = input.code;
	const complete = code.length <= MAX_CELL_CHARS;
	return {
		host: "prime",
		tool: "ipython",
		operation: "execute-cell",
		payload: { code: complete ? code : code.slice(0, MAX_CELL_CHARS) },
		cwd: canonicalCwd(cwd),
		reviewReasons: ["all Prime IPython cells require whole-cell review"],
		privacy: { privateDataRead: false },
		payloadState: {
			complete,
			originalChars: code.length,
			retainedChars: Math.min(code.length, MAX_CELL_CHARS),
		},
		inputIdentity: safeIdentity(input),
	};
}

function safeIdentity(input: unknown): string {
	try {
		return guardianInputIdentity(input);
	} catch {
		return "invalid";
	}
}

function canonicalCwd(cwd: string): string {
	const absolute = resolve(cwd);
	try {
		return realpathSync(absolute);
	} catch {
		return absolute;
	}
}

function isPlainCodeInput(input: unknown): input is { code: string } {
	if (
		typeof input !== "object" ||
		input === null ||
		Object.getPrototypeOf(input) !== Object.prototype
	) {
		return false;
	}
	const keys = Reflect.ownKeys(input);
	if (keys.length !== 1 || keys[0] !== "code") return false;
	const descriptor = Object.getOwnPropertyDescriptor(input, "code");
	return (
		!!descriptor &&
		"value" in descriptor &&
		descriptor.enumerable === true &&
		typeof descriptor.value === "string"
	);
}
