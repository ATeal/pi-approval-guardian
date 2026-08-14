import type { Context } from "@earendil-works/pi-ai";
import {
	decideGuardianAction,
	normalizePrimeIpythonAction,
	guardianInputIdentity,
	type NormalizedGuardianAction,
	type NormalizedGuardianDecision,
	type GuardianReviewResult,
} from "../src/normalized-decision.ts";
import { runIsolatedPrimeReview, type PrimeModel, type PrimeReviewerStream } from "../src/reviewer.ts";
import { lockExactToolInput } from "../src/tool-input-lock.ts";

export type PrimeTracerReviewResult =
	| { outcome: "allow" }
	| { outcome: "deny" | "failure" | "timeout"; reason?: string };
export type PrimeTracerReview = (
	action: NormalizedGuardianAction,
	signal: AbortSignal,
) => Promise<PrimeTracerReviewResult> | PrimeTracerReviewResult;
export interface PrimeToolCallEvent { toolName: string; toolCallId: string; input: unknown }
export type PrimeToolCallResult = { block: true; reason: string } | undefined;
export interface PrimeModelRegistry {
	find?(provider: string, model: string): PrimeModel | undefined;
	getApiKeyAndHeaders(model: PrimeModel): Promise<{ ok: boolean; apiKey?: string; headers?: Record<string, string>; error?: string }>;
}
export interface PrimeExtensionContext { cwd?: string; model?: PrimeModel; modelRegistry?: PrimeModelRegistry; signal?: AbortSignal }
export type PrimeToolCallHandler = (event: PrimeToolCallEvent, context: PrimeExtensionContext) => Promise<PrimeToolCallResult>;
export interface PrimeExtensionApi {
	on(name: "tool_call", handler: PrimeToolCallHandler): void;
	on(name: "turn_start", handler: () => void): void;
}
export interface PrimeApprovalGuardianTracerOptions {
	review?: PrimeTracerReview;
	reviewerModel?: string;
	timeoutMs?: number;
	streamModel?: PrimeReviewerStream;
	audit?: (decision: NormalizedGuardianDecision) => void;
}

const OUTCOMES = new Set(["allow", "deny", "failure", "timeout"]);

export function createPrimeApprovalGuardian(options: PrimeApprovalGuardianTracerOptions = {}) {
	return function primeApprovalGuardian(pi: PrimeExtensionApi): void {
		let adverseOutcomes = 0;
		pi.on("turn_start", () => { adverseOutcomes = 0; });
		pi.on("tool_call", async (event, context) => {
			if (event.toolName !== "ipython") return;
			const action = normalizePrimeIpythonAction(event.input, context.cwd ?? process.cwd());
			if (!action) return block("Prime Approval Guardian blocked malformed IPython input.");
			const decision = await decideGuardianAction(action, {
				isCircuitOpen: () => adverseOutcomes >= 3,
				review: (candidate) => reviewBeforeDeadline(candidate, context, options),
				protectInput: (identity) => lockExactToolInput(event, identity, guardianInputIdentity),
				recordCircuitOutcome: (adverse) => { adverseOutcomes = adverse ? adverseOutcomes + 1 : 0; },
			});
			options.audit?.(decision);
			if (decision.verdict === "allow") return;
			return block(reasonFor(decision.result));
		});
	};
}

async function reviewBeforeDeadline(
	action: NormalizedGuardianAction,
	context: PrimeExtensionContext,
	options: PrimeApprovalGuardianTracerOptions,
): Promise<GuardianReviewResult> {
	const controller = new AbortController();
	const signal = context.signal
		? AbortSignal.any([context.signal, controller.signal])
		: controller.signal;
	let timer: ReturnType<typeof setTimeout> | undefined;
	let removeAbortListener: () => void = () => undefined;
	try {
		const review = options.review
			? Promise.resolve()
					.then(() => options.review!(action, signal))
					.then(normalizeInjectedReview)
			: realReview(action, context, options, signal);
		const outcomes: Array<Promise<GuardianReviewResult>> = [
			review,
			new Promise((resolve) => {
				timer = setTimeout(() => {
					controller.abort();
					resolve({
						kind: "timeout",
						message:
							"Prime Approval Guardian review timeout; IPython was blocked.",
					});
				}, options.timeoutMs ?? 90_000);
			}),
		];
		if (context.signal) {
			const externalAbort = new Promise<GuardianReviewResult>((resolve) => {
				const abort = () =>
					resolve({
						kind: "failure",
						message:
							"Prime Approval Guardian review was cancelled; IPython was blocked.",
					});
				if (context.signal!.aborted) {
					abort();
					return;
				}
				context.signal!.addEventListener("abort", abort, { once: true });
				removeAbortListener = () =>
					context.signal!.removeEventListener("abort", abort);
			});
			outcomes.push(externalAbort);
		}
		return await Promise.race(outcomes);
	} catch (error) {
		const invalid =
			error instanceof Error && error.message === "invalid review result";
		return {
			kind: "failure",
			message: invalid
				? "Prime Approval Guardian received an invalid review result; IPython was blocked."
				: `Prime Approval Guardian review failed; IPython was blocked. ${error instanceof Error ? error.message : String(error)}`,
		};
	} finally {
		if (timer) clearTimeout(timer);
		removeAbortListener();
		controller.abort();
	}
}
async function realReview(action: NormalizedGuardianAction, context: PrimeExtensionContext, options: PrimeApprovalGuardianTracerOptions, signal: AbortSignal): Promise<GuardianReviewResult> {
	if (!context.modelRegistry) throw new Error("Reviewer model registry is unavailable.");
	const configured = options.reviewerModel;
	let model: PrimeModel | undefined;
	if (configured) {
		const slash = configured.indexOf("/");
		if (slash <= 0 || slash === configured.length - 1) throw new Error("Configured reviewer model must be provider/model.");
		model = context.modelRegistry.find?.(configured.slice(0, slash), configured.slice(slash + 1));
		if (!model) throw new Error(`Registered reviewer model not found: ${configured}.`);
	} else {
		model = context.model;
		if (!model) throw new Error("No explicit current-model fallback is available.");
	}
	const auth = await context.modelRegistry.getApiKeyAndHeaders(model);
	if (!auth.ok) throw new Error(`Reviewer authentication is unavailable: ${auth.error ?? "unknown authentication failure"}`);
	return runIsolatedPrimeReview(
		action,
		model,
		{
			ok: true,
			...(auth.apiKey === undefined ? {} : { apiKey: auth.apiKey }),
			...(auth.headers === undefined ? {} : { headers: auth.headers }),
		},
		signal,
		options.streamModel,
	);
}

function normalizeInjectedReview(value: unknown): GuardianReviewResult {
	if (typeof value !== "object" || value === null) throw new Error("invalid review result");
	const outcome = Reflect.get(value, "outcome"); const reason = Reflect.get(value, "reason");
	if (typeof outcome !== "string" || !OUTCOMES.has(outcome) || (reason !== undefined && typeof reason !== "string")) throw new Error("invalid review result");
	if (outcome === "allow") return { kind: "allowed", assessment: { risk_level: "low", user_authorization: "unknown", outcome: "allow", rationale: "Deterministic test reviewer allowed the action." } };
	if (outcome === "deny") return { kind: "denied", assessment: { risk_level: "high", user_authorization: "unknown", outcome: "deny", rationale: reason ?? "The reviewer denied the cell." } };
	return { kind: outcome, message: reason ?? `Prime Approval Guardian ${outcome}.` } as GuardianReviewResult;
}
function reasonFor(result: GuardianReviewResult): string {
	if (result.kind === "denied") return result.assessment.rationale;
	if (result.kind === "allowed") return "Prime Approval Guardian blocked an inconsistent allow decision.";
	return result.message;
}
function block(reason: string): { block: true; reason: string } { return { block: true, reason }; }

export { decideGuardianAction, normalizePrimeIpythonAction, guardianInputIdentity } from "../src/normalized-decision.ts";
export type { NormalizedGuardianAction, NormalizedGuardianDecision, GuardianReviewResult } from "../src/normalized-decision.ts";
export default createPrimeApprovalGuardian();
