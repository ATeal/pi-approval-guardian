import { resolveGuardianPath, type GuardianReviewResult } from "./gate.ts";
import type { GuardianAction } from "./review.ts";
import {
	decideGuardianAction,
	enforceNormalizedActionRequirements,
	guardianInputIdentity,
	type NormalizedGuardianAction,
} from "./shared-decision.ts";

const NORMALIZED_PAYLOAD_COMMAND_CHARS = 64_000;

export type {
	GuardianDecisionAudit,
	GuardianDecisionServices,
	NormalizedGuardianAction,
	NormalizedGuardianDecision,
} from "./shared-decision.ts";
export { decideGuardianAction, guardianInputIdentity } from "./shared-decision.ts";

export function normalizePiBashAction(
	action: GuardianAction,
	input: unknown,
): NormalizedGuardianAction {
	const privateDataRead = action.payload.private_data_read === true;
	const command = boundedCommand(action.payload.command);
	return {
		host: "pi",
		tool: "bash",
		operation: "execute",
		payload: {
			command: command.value,
			private_data_read: privateDataRead,
		},
		cwd: resolveGuardianPath(".", action.cwd).projectRoot,
		reviewReasons: [
			"bash.command configured for review",
			...(privateDataRead ? ["private data read"] : []),
		],
		privacy: { privateDataRead },
		payloadState: {
			complete: command.complete,
			originalChars: command.originalChars,
			retainedChars: command.value.length,
		},
		inputIdentity: normalizedInputIdentity(input),
	};
}

export function enforceActionRequirements(
	action: GuardianAction | NormalizedGuardianAction,
	result: GuardianReviewResult,
): GuardianReviewResult {
	const normalized = "privacy" in action
		? action
		: {
				payload: action.payload,
				privacy: { privateDataRead: action.payload.private_data_read === true },
			};
	return enforceNormalizedActionRequirements(normalized, result);
}

function boundedCommand(value: unknown): {
	value: string;
	complete: boolean;
	originalChars: number;
} {
	const command = String(value ?? "");
	if (command.length <= NORMALIZED_PAYLOAD_COMMAND_CHARS) {
		return { value: command, complete: true, originalChars: command.length };
	}
	const marker = "<guardian_action_truncated />";
	const retained = Math.max(0, NORMALIZED_PAYLOAD_COMMAND_CHARS - marker.length);
	const prefix = Math.floor(retained / 2);
	return {
		value: `${command.slice(0, prefix)}${marker}${command.slice(command.length - (retained - prefix))}`,
		complete: false,
		originalChars: command.length,
	};
}

function normalizedInputIdentity(input: unknown): string {
	try {
		return guardianInputIdentity(input);
	} catch {
		return "invalid";
	}
}
