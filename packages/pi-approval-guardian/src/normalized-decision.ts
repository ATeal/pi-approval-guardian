import { createHash } from "node:crypto";
import {
	circuitOutcomeForReview,
	resolveGuardianPath,
	type GuardianReviewResult,
} from "./gate.ts";
import type { GuardianAction } from "./review.ts";

const NORMALIZED_PAYLOAD_COMMAND_CHARS = 64_000;

export interface NormalizedGuardianAction extends GuardianAction {
	host: "pi" | "prime";
	operation: string;
	reviewReasons: string[];
	privacy: { privateDataRead: boolean };
	payloadState: {
		complete: boolean;
		originalChars: number;
		retainedChars: number;
	};
	inputIdentity: string;
}

export interface GuardianDecisionAudit {
	host: NormalizedGuardianAction["host"];
	tool: string;
	operation: string;
	inputIdentity: string;
	outcome: GuardianReviewResult["kind"];
}

export interface NormalizedGuardianDecision {
	verdict: "allow" | "block";
	result: GuardianReviewResult;
	audit: GuardianDecisionAudit;
}

export interface GuardianDecisionServices {
	isCircuitOpen(): boolean;
	review(action: NormalizedGuardianAction): Promise<GuardianReviewResult>;
	protectInput(expectedInputIdentity: string): void;
	recordCircuitOutcome(adverse: boolean): void;
}

export function normalizePiBashAction(
	action: GuardianAction,
	input: unknown,
): NormalizedGuardianAction {
	const privateDataRead = action.payload.private_data_read === true;
	const command = boundedCommand(action.payload.command);
	const inputIdentity = normalizedInputIdentity(input);
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
		inputIdentity,
	};
}

export async function decideGuardianAction(
	action: NormalizedGuardianAction,
	services: GuardianDecisionServices,
): Promise<NormalizedGuardianDecision> {
	let result: GuardianReviewResult;
	if (services.isCircuitOpen()) {
		result = {
			kind: "circuit-open",
			message: "Repeated adverse Guardian outcomes reached the per-turn limit.",
		};
	} else {
		if (!inputIdentityIsValid(action.inputIdentity)) {
			result = {
				kind: "failure",
				message:
					"Normalized action input identity could not be computed safely; approval review was not attempted.",
			};
		} else if (!action.payloadState.complete) {
			result = {
				kind: "failure",
				message:
					"Normalized action payload exceeded its safety limit and is incomplete; approval review was not attempted.",
			};
		} else {
			try {
				result = enforceActionRequirements(
					action,
					await services.review(action),
				);
			} catch (error) {
				result = {
					kind: "failure",
					message: `Automatic approval review failed: ${error instanceof Error ? error.message : String(error)}`,
				};
			}
		}
		if (result.kind === "allowed") {
			try {
				services.protectInput(action.inputIdentity);
			} catch (error) {
				result = {
					kind: "failure",
					message: `Approved tool input could not be locked safely: ${error instanceof Error ? error.message : String(error)}`,
				};
			}
		}
		const circuitOutcome = circuitOutcomeForReview(result);
		if (circuitOutcome !== undefined) {
			services.recordCircuitOutcome(circuitOutcome);
		}
	}
	return {
		verdict: result.kind === "allowed" ? "allow" : "block",
		result,
		audit: {
			host: action.host,
			tool: action.tool,
			operation: action.operation,
			inputIdentity: action.inputIdentity,
			outcome: result.kind,
		},
	};
}

export function enforceActionRequirements(
	action: GuardianAction | NormalizedGuardianAction,
	result: GuardianReviewResult,
): GuardianReviewResult {
	if (result.kind !== "allowed") return result;
	const { risk_level: risk, user_authorization: authorization } =
		result.assessment;
	let rationale: string | undefined;
	if (risk === "critical") {
		rationale = "Critical-risk actions cannot be automatically approved.";
	} else if (
		risk === "high" &&
		(authorization === "unknown" || authorization === "low")
	) {
		rationale =
			"High-risk actions require at least medium user authorization.";
	} else if (privateDataReadForAction(action) && authorization !== "high") {
		rationale =
			"The private-data read lacks explicit high user authorization. Explain the exact source and purpose, then wait for the user to authorize it in conversation before retrying.";
	}
	if (!rationale) return result;
	return {
		kind: "denied",
		assessment: {
			...result.assessment,
			outcome: "deny",
			rationale,
		},
	};
}

function privateDataReadForAction(
	action: GuardianAction | NormalizedGuardianAction,
): boolean {
	return "privacy" in action
		? action.privacy.privateDataRead
		: action.payload.private_data_read === true;
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

export function guardianInputIdentity(value: unknown): string {
	return `sha256:${createHash("sha256")
		.update(canonicalJson(value), "utf8")
		.digest("hex")}`;
}

function inputIdentityIsValid(value: string): boolean {
	return /^sha256:[a-f0-9]{64}$/.test(value);
}

function normalizedInputIdentity(input: unknown): string {
	try {
		return guardianInputIdentity(input);
	} catch {
		return "invalid";
	}
}

function canonicalJson(value: unknown, active = new WeakSet<object>()): string {
	if (value === null || typeof value === "string" || typeof value === "boolean") {
		return JSON.stringify(value);
	}
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw new Error("non-finite input number");
		return JSON.stringify(value);
	}
	if (typeof value !== "object") {
		throw new Error(`non-JSON input ${typeof value}`);
	}
	if (active.has(value)) throw new Error("cyclic input");
	active.add(value);
	try {
		if (Array.isArray(value)) {
			if (Object.getPrototypeOf(value) !== Array.prototype) {
				throw new Error("input array has a custom prototype");
			}
			const keys = Reflect.ownKeys(value).filter((key) => key !== "length");
			if (keys.length !== value.length) throw new Error("invalid input array shape");
			const entries: string[] = [];
			for (let index = 0; index < value.length; index++) {
				const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
				if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
					throw new Error("invalid input array entry");
				}
				entries.push(canonicalJson(descriptor.value, active));
			}
			return `[${entries.join(",")}]`;
		}
		const prototype = Object.getPrototypeOf(value);
		if (prototype !== Object.prototype && prototype !== null) {
			throw new Error("input is not a plain object");
		}
		const keys = Reflect.ownKeys(value);
		if (keys.some((key) => typeof key === "symbol")) {
			throw new Error("symbol-keyed input property");
		}
		return `{${(keys as string[])
			.sort()
			.map((key) => {
				const descriptor = Object.getOwnPropertyDescriptor(value, key);
				if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
					throw new Error("invalid input property");
				}
				return `${JSON.stringify(key)}:${canonicalJson(descriptor.value, active)}`;
			})
			.join(",")}}`;
	} finally {
		active.delete(value);
	}
}
