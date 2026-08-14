export interface PrimeTracerReviewRequest {
	tool: "ipython";
	toolCallId: string;
	code: string;
}

export type PrimeTracerReviewResult =
	| { outcome: "allow" }
	| {
			outcome: "deny" | "failure" | "timeout";
			reason?: string;
		};

export type PrimeTracerReview = (
	request: PrimeTracerReviewRequest,
) => Promise<PrimeTracerReviewResult> | PrimeTracerReviewResult;

export interface PrimeToolCallEvent {
	toolName: string;
	toolCallId: string;
	input: unknown;
}

export type PrimeToolCallResult =
	| { block: true; reason: string }
	| undefined;

export type PrimeToolCallHandler = (
	event: PrimeToolCallEvent,
	context: unknown,
) => Promise<PrimeToolCallResult>;

export interface PrimeExtensionApi {
	on(name: "tool_call", handler: PrimeToolCallHandler): void;
}

export interface PrimeApprovalGuardianTracerOptions {
	review: PrimeTracerReview;
	timeoutMs?: number;
}

const REVIEW_OUTCOMES = new Set(["allow", "deny", "failure", "timeout"]);

function normalizeReviewResult(value: unknown): PrimeTracerReviewResult {
	if (typeof value !== "object" || value === null) {
		throw new Error("invalid review result");
	}
	const outcome = Reflect.get(value, "outcome");
	const reason = Reflect.get(value, "reason");
	if (typeof outcome !== "string" || !REVIEW_OUTCOMES.has(outcome)) {
		throw new Error("invalid review result");
	}
	if (reason !== undefined && typeof reason !== "string") {
		throw new Error("invalid review result");
	}
	return reason === undefined
		? ({ outcome } as PrimeTracerReviewResult)
		: ({ outcome, reason } as PrimeTracerReviewResult);
}

export function createPrimeApprovalGuardian(
	options: PrimeApprovalGuardianTracerOptions,
) {
	return function primeApprovalGuardian(pi: PrimeExtensionApi): void {
		pi.on("tool_call", async (event) => {
			if (event.toolName !== "ipython") return;
			if (
				typeof event.input !== "object" ||
				event.input === null ||
				!("code" in event.input) ||
				typeof event.input.code !== "string"
			) {
				return {
					block: true,
					reason: "Prime Approval Guardian blocked malformed IPython input.",
				};
			}
			let result: PrimeTracerReviewResult;
			let timeout: ReturnType<typeof setTimeout> | undefined;
			try {
				const request = {
					tool: "ipython" as const,
					toolCallId: event.toolCallId,
					code: event.input.code,
				};
				const timeoutMs = options.timeoutMs ?? 90_000;
				const rawResult: unknown = await Promise.race([
					Promise.resolve().then(() => options.review(request)),
					new Promise<PrimeTracerReviewResult>((resolveTimeout) => {
						timeout = setTimeout(
							() =>
								resolveTimeout({
									outcome: "timeout",
									reason: "Prime Approval Guardian review timeout; IPython was blocked.",
								}),
							timeoutMs,
						);
					}),
				]);
				result = normalizeReviewResult(rawResult);
			} catch (error) {
				const invalidResult =
					error instanceof Error && error.message === "invalid review result";
				return {
					block: true,
					reason: invalidResult
						? "Prime Approval Guardian received an invalid review result; IPython was blocked."
						: "Prime Approval Guardian review failed; IPython was blocked.",
				};
			} finally {
				if (timeout) clearTimeout(timeout);
			}
			if (result.outcome === "allow") return;
			return {
				block: true,
				reason:
					result.reason ??
					`Prime Approval Guardian blocked IPython after ${result.outcome}.`,
			};
		});
	};
}

const failClosedReview: PrimeTracerReview = () => ({
	outcome: "failure",
	reason:
		"Prime Approval Guardian tracer has no configured reviewer; IPython is blocked fail closed.",
});

export default createPrimeApprovalGuardian({ review: failClosedReview });
