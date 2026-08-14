import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";
import primeApprovalGuardian, {
	createPrimeApprovalGuardian,
	type PrimeExtensionApi,
	type PrimeToolCallHandler,
	type PrimeTracerReview,
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
	assert.deepEqual(requests, [
		{ tool: "ipython", toolCallId: "cell-1", code: "1 + 1" },
	]);
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
	assert.match(result?.reason ?? "", /no configured reviewer/i);
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
