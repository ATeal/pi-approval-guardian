import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import primeApprovalGuardian, {
	createPrimeApprovalGuardian,
	type PrimeExtensionApi,
	type PrimeToolCallHandler,
	type PrimeTracerReview,
	type PrimeTracerReviewResult,
} from "../../prime-approval-guardian/extensions/index.ts";

function loadPrimeToolCallHandler(review: PrimeTracerReview): PrimeToolCallHandler {
	const handlers = new Map<string, PrimeToolCallHandler>();
	createPrimeApprovalGuardian({ review })(
		{
			on(name: string, handler: PrimeToolCallHandler) {
				handlers.set(name, handler);
			},
		} as PrimeExtensionApi,
	);
	const handler = handlers.get("tool_call");
	assert.ok(handler, "the Prime extension must register tool-call preflight");
	return handler;
}

test("allows a benign IPython cell after the deterministic reviewer allows it", async () => {
	const requests: unknown[] = [];
	const handler = loadPrimeToolCallHandler(async (request) => {
		requests.push(request);
		return { outcome: "allow" };
	});

	const result = await handler(
		{
			toolName: "ipython",
			toolCallId: "cell-1",
			input: { code: "1 + 1" },
		},
		{},
	);

	assert.equal(result, undefined);
	assert.equal(requests.length, 1);
	assert.deepEqual(requests[0], {
		host: "prime",
		tool: "ipython",
		operation: "execute-cell",
		payload: { code: "1 + 1" },
		cwd: realpathSync(process.cwd()),
		reviewReasons: ["all Prime IPython cells require whole-cell review"],
		privacy: { privateDataRead: false },
		payloadState: { complete: true, originalChars: 5, retainedChars: 5 },
		inputIdentity: requests[0] && (requests[0] as { inputIdentity: string }).inputIdentity,
	});
	assert.match((requests[0] as { inputIdentity: string }).inputIdentity, /^sha256:[a-f0-9]{64}$/);
});


test("blocks a denied IPython cell before it can produce a side effect", async () => {
	const handler = loadPrimeToolCallHandler(() => ({
		outcome: "deny",
		reason: "The tracer reviewer denied the cell.",
	}));
	let sideEffect = false;

	const result = await handler(
		{
			toolName: "ipython",
			toolCallId: "cell-denied",
			input: { code: "side_effect()" },
		},
		{},
	);
	if (!result?.block) sideEffect = true;

	assert.deepEqual(result, {
		block: true,
		reason: "The tracer reviewer denied the cell.",
	});
	assert.equal(sideEffect, false);
});


test("fails closed when the tracer reviewer throws", async () => {
	const handler = loadPrimeToolCallHandler(() => {
		throw new Error("reviewer unavailable");
	});

	const result = await handler(
		{
			toolName: "ipython",
			toolCallId: "cell-failure",
			input: { code: "write_marker()" },
		},
		{},
	);

	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /review failed/i);
});


test("fails closed on an invalid tracer review result", async () => {
	const handler = loadPrimeToolCallHandler(
		(() => ({ outcome: "unexpected" })) as unknown as PrimeTracerReview,
	);

	const result = await handler(
		{
			toolName: "ipython",
			toolCallId: "cell-invalid",
			input: { code: "write_marker()" },
		},
		{},
	);

	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /invalid review result/i);
});


test("packs an explicit Prime-only compatibility tracer", () => {
	const packageDirectory = new URL(
		"../../prime-approval-guardian/",
		import.meta.url,
	);
	const manifest = JSON.parse(
		readFileSync(new URL("package.json", packageDirectory), "utf8"),
	) as {
		name: string;
		description: string;
		keywords: string[];
		pi: { extensions: string[] };
		primeAgent: { compatibility: string };
	};
	const packOutput = JSON.parse(
		execFileSync("npm", ["pack", "--dry-run", "--json"], {
			cwd: fileURLToPath(packageDirectory),
			encoding: "utf8",
		}),
	) as
		| Array<{ files: Array<{ path: string }> }>
		| Record<string, { files: Array<{ path: string }> }>;
	const packed = Array.isArray(packOutput)
		? packOutput
		: Object.values(packOutput);
	const files = packed[0]?.files.map(({ path }) => path) ?? [];

	assert.equal(manifest.name, "prime-approval-guardian");
	assert.equal(manifest.primeAgent.compatibility, ">=0.7.2 <0.8.0");
	assert.deepEqual(manifest.pi.extensions, ["./extensions/index.ts"]);
	assert.ok(manifest.keywords.includes("prime-agent-extension"));
	assert.ok(!manifest.keywords.includes("pi-extension"));
	assert.match(manifest.description, /Prime Agent/);
	assert.ok(files.includes("extensions/index.ts"));
	assert.ok(files.includes("src/normalized-decision.ts"));
	assert.ok(files.includes("src/shared-decision.ts"));
	assert.ok(files.includes("src/reviewer.ts"));
	assert.equal(
		readFileSync(new URL("src/shared-decision.ts", packageDirectory), "utf8"),
		readFileSync(new URL("../src/shared-decision.ts", import.meta.url), "utf8"),
		"the packed Prime copy must exactly match the shared Guardian decision source",
	);
	assert.ok(files.includes("README.md"));
	assert.ok(files.includes("LICENSES/Apache-2.0.txt"));
});


test("blocks explicit failure and timeout outcomes", async (t) => {
	for (const outcome of ["failure", "timeout"] as const) {
		await t.test(outcome, async () => {
			const handler = loadPrimeToolCallHandler(() => ({ outcome }));
			const result = await handler(
				{
					toolName: "ipython",
					toolCallId: `cell-${outcome}`,
					input: { code: "write_marker()" },
				},
				{},
			);
			assert.equal(result?.block, true);
			assert.match(result?.reason ?? "", new RegExp(outcome, "i"));
		});
	}
});

test("blocks malformed IPython input without consulting the reviewer", async () => {
	let reviewed = false;
	const handler = loadPrimeToolCallHandler(() => {
		reviewed = true;
		return { outcome: "allow" };
	});
	const result = await handler(
		{ toolName: "ipython", toolCallId: "malformed", input: {} },
		{},
	);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /malformed IPython input/i);
	assert.equal(reviewed, false);
});

test("leaves non-IPython tools outside this Prime-only tracer", async () => {
	let reviewed = false;
	const handler = loadPrimeToolCallHandler(() => {
		reviewed = true;
		return { outcome: "deny" };
	});
	const result = await handler(
		{
			toolName: "custom-tool",
			toolCallId: "custom",
			input: { code: "not an IPython contract" },
		},
		{},
	);
	assert.equal(result, undefined);
	assert.equal(reviewed, false);
});

test("the packaged default extension blocks IPython without a reviewer", async () => {
	const handlers = new Map<string, PrimeToolCallHandler>();
	primeApprovalGuardian({
		on(name: string, handler: PrimeToolCallHandler) {
			handlers.set(name, handler);
		},
	} as PrimeExtensionApi);
	const handler = handlers.get("tool_call");
	assert.ok(handler);
	const result = await handler(
		{
			toolName: "ipython",
			toolCallId: "default-fail-closed",
			input: { code: "write_marker()" },
		},
		{},
	);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /model registry is unavailable/i);
});


test("fails closed when a reviewer returns a non-string reason", async () => {
	const handler = loadPrimeToolCallHandler(
		(() => ({ outcome: "deny", reason: 42 })) as unknown as PrimeTracerReview,
	);
	const result = await handler(
		{
			toolName: "ipython",
			toolCallId: "invalid-reason",
			input: { code: "write_marker()" },
		},
		{},
	);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /invalid review result/i);
});

test("fails closed when reviewer result inspection throws", async () => {
	const hostileResult = new Proxy(
		{},
		{
			has() {
				throw new Error("hostile result");
			},
		},
	);
	const handler = loadPrimeToolCallHandler(
		(() => hostileResult) as unknown as PrimeTracerReview,
	);
	const result = await handler(
		{
			toolName: "ipython",
			toolCallId: "hostile-result",
			input: { code: "write_marker()" },
		},
		{},
	);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /invalid review result|review failed/i);
});


test("turns a hung reviewer into a blocking timeout", async () => {
	const handlers = new Map<string, PrimeToolCallHandler>();
	createPrimeApprovalGuardian({
		timeoutMs: 10,
		review: () => new Promise(() => undefined),
	})({
		on(name: string, handler: PrimeToolCallHandler) {
			handlers.set(name, handler);
		},
	} as PrimeExtensionApi);
	const handler = handlers.get("tool_call");
	assert.ok(handler);
	const started = Date.now();
	const result = await handler(
		{
			toolName: "ipython",
			toolCallId: "hung-reviewer",
			input: { code: "write_marker()" },
		},
		{},
	);
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /timeout/i);
	assert.ok(Date.now() - started < 1_000, "preflight must not hang indefinitely");
});


test("the real reviewer uses the current registered model in an isolated tool-free context", async () => {
	const model = { provider: "native-review", id: "safe", api: "fake" };
	const streamCalls: unknown[] = [];
	const handler = (() => {
		const handlers = new Map<string, PrimeToolCallHandler>();
		createPrimeApprovalGuardian({
			streamModel: async (selected, context, auth, signal) => {
				streamCalls.push({ selected, context, auth, signal: signal instanceof AbortSignal });
				return JSON.stringify({
					risk_level: "low",
					user_authorization: "unknown",
					outcome: "allow",
					rationale: "Pure calculation.",
				});
			},
		})({ on: (name, fn) => handlers.set(name, fn as PrimeToolCallHandler) } as PrimeExtensionApi);
		return handlers.get("tool_call")!;
	})();
	const context = {
		cwd: process.cwd(),
		model,
		modelRegistry: {
			find: () => undefined,
			getApiKeyAndHeaders: async () => ({ ok: true, headers: { authorization: "opaque" } }),
		},
		signal: undefined,
	};
	const event = { toolName: "ipython", toolCallId: "real", input: { code: "2 + 2" } };
	assert.equal(await handler(event, context), undefined);
	assert.equal(Object.isFrozen(event.input), true);
	assert.deepEqual(streamCalls, [{
		selected: model,
		context: {
			systemPrompt: (streamCalls[0] as any).context.systemPrompt,
			messages: [{ role: "user", content: [{ type: "text", text: (streamCalls[0] as any).context.messages[0].content[0].text }], timestamp: (streamCalls[0] as any).context.messages[0].timestamp }],
			tools: [],
		},
		auth: { ok: true, headers: { authorization: "opaque" } },
		signal: true,
	}]);
	assert.match((streamCalls[0] as any).context.systemPrompt, /never execute/i);
	assert.match((streamCalls[0] as any).context.messages[0].content[0].text, /"host":"prime"/);
	assert.doesNotMatch(JSON.stringify((streamCalls[0] as any).context), /codex-auto-review/i);
});

test("a configured reviewer model is resolved without synthesizing codex-auto-review", async () => {
	const configured = { provider: "registered", id: "reviewer", api: "fake" };
	let selected: unknown;
	const handlers = new Map<string, PrimeToolCallHandler>();
	createPrimeApprovalGuardian({
		reviewerModel: "registered/reviewer",
		streamModel: async (model) => {
			selected = model;
			return '{"risk_level":"low","user_authorization":"unknown","outcome":"allow","rationale":"safe"}';
		},
	})({ on: (name, fn) => handlers.set(name, fn as PrimeToolCallHandler) } as PrimeExtensionApi);
	const result = await handlers.get("tool_call")!(
		{ toolName: "ipython", toolCallId: "registered", input: { code: "3 + 3" } },
		{
			cwd: process.cwd(),
			model: { provider: "main", id: "current", api: "fake" },
			modelRegistry: {
				find: (provider: string, id: string) => provider === "registered" && id === "reviewer" ? configured : undefined,
				getApiKeyAndHeaders: async () => ({ ok: true }),
			},
		},
	);
	assert.equal(result, undefined);
	assert.equal(selected, configured);
});

test("default real review blocks auth, provider, invalid assessment, deny and timeout without side effects", async (t) => {
	for (const scenario of ["auth", "provider", "invalid", "type-confusion", "deny", "timeout"] as const) {
		await t.test(scenario, async () => {
			let sideEffect = false;
			const handlers = new Map<string, PrimeToolCallHandler>();
			createPrimeApprovalGuardian({
				timeoutMs: 10,
				streamModel: async () => {
					if (scenario === "provider") throw new Error("provider unavailable");
					if (scenario === "timeout") return new Promise<string>(() => undefined);
					if (scenario === "invalid") return "not json";
					if (scenario === "type-confusion") {
						return JSON.stringify({
							risk_level: ["critical"],
							user_authorization: "unknown",
							outcome: "allow",
							rationale: "must not bypass strict parsing",
						});
					}
					return JSON.stringify({ risk_level: "high", user_authorization: "unknown", outcome: "deny", rationale: "denied" });
				},
			})({ on: (name, fn) => handlers.set(name, fn as PrimeToolCallHandler) } as PrimeExtensionApi);
			const result = await handlers.get("tool_call")!(
				{ toolName: "ipython", toolCallId: scenario, input: { code: "side_effect()" } },
				{
					cwd: process.cwd(),
					model: { provider: "native", id: "current", api: "fake" },
					modelRegistry: { getApiKeyAndHeaders: async () => scenario === "auth" ? ({ ok: false, error: "missing" }) : ({ ok: true }) },
				},
			);
			if (!result?.block) sideEffect = true;
			assert.equal(result?.block, true);
			assert.equal(sideEffect, false);
		});
	}
});

test("fails closed for incomplete and untrusted whole-cell inputs", async (t) => {
	for (const [name, input] of [
		["incomplete", { code: "x".repeat(64_001) }],
		["untrusted", Object.assign(Object.create({ inherited: true }), { code: "1 + 1" })],
	] as const) {
		await t.test(name, async () => {
			let reviewed = false;
			const handler = loadPrimeToolCallHandler(() => { reviewed = true; return { outcome: "allow" }; });
			const result = await handler({ toolName: "ipython", toolCallId: name, input }, { cwd: process.cwd() });
			assert.equal(result?.block, true);
			assert.equal(reviewed, false);
		});
	}
});


test("external cancellation blocks immediately and aborts a late reviewer", async () => {
	const handlers = new Map<string, PrimeToolCallHandler>();
	const controller = new AbortController();
	let reviewerSignal: AbortSignal | undefined;
	let settleReview: ((value: PrimeTracerReviewResult) => void) | undefined;
	createPrimeApprovalGuardian({
		timeoutMs: 60_000,
		review: (_action, signal) => {
			reviewerSignal = signal;
			return new Promise((resolve) => {
				settleReview = resolve;
			});
		},
	})({ on: (name, fn) => handlers.set(name, fn as PrimeToolCallHandler) } as PrimeExtensionApi);
	const pending = handlers.get("tool_call")!(
		{ toolName: "ipython", toolCallId: "cancelled", input: { code: "side_effect()" } },
		{ cwd: process.cwd(), signal: controller.signal },
	);
	controller.abort();
	const result = await pending;
	assert.equal(result?.block, true);
	assert.match(result?.reason ?? "", /cancelled/i);
	assert.equal(reviewerSignal?.aborted, true);
	settleReview?.({ outcome: "allow" });
	await Promise.resolve();
	assert.equal(result?.block, true, "late reviewer settlement cannot change the decision");
});
