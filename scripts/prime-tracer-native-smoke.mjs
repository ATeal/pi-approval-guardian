import { spawn, spawnSync } from "node:child_process";
import {
	copyFileSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageDirectory = join(repository, "packages", "prime-approval-guardian");
const fakeProviderFixture = join(
	repository,
	"packages",
	"pi-approval-guardian",
	"tests",
	"fixtures",
	"prime-tracer",
	"fake-provider.ts",
);
const temporary = mkdtempSync(join(tmpdir(), "prime-guardian-native-"));
const fakeProvider = join(temporary, "fake-provider.ts");
const workingDirectory = join(temporary, "project");
const agentDirectory = join(temporary, "agent");
const installPrefix = join(temporary, "install");
const daemonSocket = join(temporary, "daemon.sock");
let daemon;

mkdirSync(workingDirectory);
copyFileSync(fakeProviderFixture, fakeProvider);

function run(command, args, options = {}) {
	const result = spawnSync(command, args, {
		encoding: "utf8",
		env: smokeEnvironment(options.marker),
		...options,
	});
	if (result.status !== 0) {
		throw new Error(
			`${command} ${args.join(" ")} failed (${result.status})\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
		);
	}
	return result;
}

function smokeEnvironment(marker) {
	const environment = {
		...process.env,
		PI_CODING_AGENT_DIR: agentDirectory,
		PI_OFFLINE: "1",
		PI_SKIP_VERSION_CHECK: "1",
	};
	if (marker) environment.PRIME_GUARDIAN_SMOKE_MARKER = marker;
	const managedPython = join(
		process.env.HOME ?? "",
		".prime",
		"agent",
		"kernel-venv",
		"bin",
		"python",
	);
	if (!environment.PRIME_AGENT_KERNEL_PYTHON && existsSync(managedPython)) {
		environment.PRIME_AGENT_KERNEL_PYTHON = managedPython;
	}
	return environment;
}

function packArtifact() {
	const result = run(
		"npm",
		["pack", "--json", "--pack-destination", temporary],
		{ cwd: packageDirectory },
	);
	const output = JSON.parse(result.stdout);
	const record = Array.isArray(output) ? output[0] : Object.values(output)[0];
	if (!record?.filename) throw new Error("npm pack did not return a filename");
	return join(temporary, record.filename);
}

function installArtifact(tarball) {
	run("npm", [
		"install",
		"--prefix",
		installPrefix,
		"--ignore-scripts",
		"--omit=dev",
		"--legacy-peer-deps",
		tarball,
	]);
	const installed = join(
		installPrefix,
		"node_modules",
		"prime-approval-guardian",
	);
	run("prime-agent", ["package", "install", installed]);
	const listed = run("prime-agent", ["package", "list"]);
	if (!listed.stdout.includes("prime-approval-guardian")) {
		throw new Error(`Prime Agent did not list the installed tracer:\n${listed.stdout}`);
	}
	return installed;
}

function writeReviewExtension(installed, name, optionsSource) {
	const path = join(temporary, `${name}-extension.ts`);
	writeFileSync(
		path,
		`import { createPrimeApprovalGuardian } from ${JSON.stringify(pathToFileURL(join(installed, "extensions", "index.ts")).href)};\nexport default createPrimeApprovalGuardian(${optionsSource});\n`,
	);
	return path;
}

function commonArguments({ extension, discoverInstalled = false }) {
	const args = [
		"--offline",
		"--daemon-socket",
		daemonSocket,
		"--cwd",
		workingDirectory,
		"--no-session",
	];
	if (!discoverInstalled) args.push("--no-extensions");
	if (extension) args.push("-e", extension);
	args.push(
		"-e",
		fakeProvider,
		"--no-skills",
		"--no-prompt-templates",
		"--no-themes",
		"--no-context-files",
		"--provider",
		"native-smoke",
		"--model",
		"deterministic",
		"--tools",
		"ipython",
	);
	return args;
}

function expectPrint(expected, marker, options) {
	rmSync(marker, { force: true });
	const result = run(
		"prime-agent",
		[...commonArguments(options), "-p", "native smoke"],
		{ marker },
	);
	if (result.stdout.trim() !== expected) {
		throw new Error(`Expected ${expected}, received ${JSON.stringify(result.stdout)}`);
	}
	return existsSync(marker);
}

function expectRpcBlock(marker) {
	rmSync(marker, { force: true });
	const result = run(
		"prime-agent",
		[...commonArguments({ discoverInstalled: true }), "--mode", "rpc"],
		{
			marker,
			input: '{"id":"p1","type":"prompt","message":"native smoke"}\n',
		},
	);
	const records = result.stdout
		.split("\n")
		.filter(Boolean)
		.map((line) => JSON.parse(line));
	const serialized = JSON.stringify(records);
	if (!serialized.includes("tool_execution_start") || !serialized.includes("ipython")) {
		throw new Error("RPC smoke did not observe IPython execution preflight");
	}
	if (!serialized.includes("BLOCKED_OK")) {
		throw new Error("RPC smoke did not observe the fail-closed result");
	}
	if (existsSync(marker)) throw new Error("blocked RPC cell produced a side effect");
}

async function startDaemon() {
	daemon = spawn(
		"prime-agent",
		["--offline", "--mode", "daemon", "--daemon-socket", daemonSocket],
		{
			env: smokeEnvironment(),
			stdio: ["ignore", "pipe", "pipe"],
		},
	);
	let stderr = "";
	daemon.stderr.on("data", (chunk) => {
		stderr += chunk;
	});
	for (let attempt = 0; attempt < 100; attempt++) {
		if (existsSync(daemonSocket)) return;
		if (daemon.exitCode !== null) {
			throw new Error(`Prime daemon exited before startup: ${stderr}`);
		}
		await new Promise((resolveDelay) => setTimeout(resolveDelay, 50));
	}
	throw new Error(`Prime daemon socket was not created: ${stderr}`);
}

async function stopDaemon() {
	if (!daemon || daemon.exitCode !== null) return;
	const exited = new Promise((resolveExit) => daemon.once("exit", resolveExit));
	daemon.kill("SIGTERM");
	await Promise.race([
		exited,
		new Promise((resolveDelay) => setTimeout(resolveDelay, 2_000)),
	]);
	if (daemon.exitCode === null) {
		daemon.kill("SIGKILL");
		await exited;
	}
}

try {
	const versionResult = run("prime-agent", ["-v"]);
	const versionOutput = `${versionResult.stdout}\n${versionResult.stderr}`.trim();
	const version = versionOutput.match(
		/(?:^|\n)(\d+)\.(\d+)\.(\d+)(?:[-+][^\s]+)?(?:$|\n)/,
	);
	if (
		!version ||
		Number(version[1]) !== 0 ||
		Number(version[2]) !== 7 ||
		Number(version[3]) < 2
	) {
		throw new Error(
			`Unsupported Prime Agent for tracer smoke: ${versionOutput || "unknown"}`,
		);
	}
	const installed = installArtifact(packArtifact());
	const allowExtension = writeReviewExtension(
		installed,
		"allow",
		'{ review: () => ({ outcome: "allow" }) }',
	);
	const blockedReviews = [
		[
			"deny",
			'{ review: () => ({ outcome: "deny", reason: "native deny" }) }',
		],
		[
			"failure",
			'{ review: () => ({ outcome: "failure", reason: "native failure" }) }',
		],
		[
			"timeout",
			"{ timeoutMs: 10, review: () => new Promise(() => undefined) }",
		],
		[
			"invalid",
			'{ review: (() => ({ outcome: "allow", reason: 42 })) as any }',
		],
	];
	const blockedMarker = join(temporary, "blocked.marker");
	const allowedMarker = join(temporary, "allowed.marker");
	if (expectPrint("BLOCKED_OK", blockedMarker, { discoverInstalled: true })) {
		throw new Error("blocked default-review cell produced a side effect");
	}
	for (const [name, optionsSource] of blockedReviews) {
		const extension = writeReviewExtension(installed, name, optionsSource);
		if (
			expectPrint("BLOCKED_OK", join(temporary, `${name}.marker`), {
				extension,
			})
		) {
			throw new Error(`${name} review produced a side effect`);
		}
	}
	if (!expectPrint("ALLOW_OK", allowedMarker, { extension: allowExtension })) {
		throw new Error("allowed print cell did not produce its expected side effect");
	}
	expectRpcBlock(join(temporary, "rpc-blocked.marker"));
	await startDaemon();
	if (
		expectPrint("BLOCKED_OK", join(temporary, "daemon-blocked.marker"), {
			discoverInstalled: true,
		})
	) {
		throw new Error("blocked daemon-backed print cell produced a side effect");
	}
	console.log(
		"Prime Agent native tracer smoke passed: print allow/deny/failure/timeout/invalid, RPC block, daemon-backed block.",
	);
} finally {
	await stopDaemon();
	rmSync(temporary, { recursive: true, force: true });
}
