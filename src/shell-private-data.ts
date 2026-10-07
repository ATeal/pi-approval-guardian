import { homedir } from "node:os";
import { classifyReadPath } from "./gate.ts";
import {
	isPrivateReadBasename,
	PRIVATE_CONFIG_GLOB_DIRECTORY_CANDIDATES,
	PRIVATE_GLOB_DIRECTORY_CANDIDATES,
	PRIVATE_GLOB_FILE_CANDIDATES,
} from "./path-rules.ts";

/**
 * Conservatively identifies shell actions that reference deterministic private
 * paths. Literal path candidates are classified by the same classifyReadPath()
 * rules used for read/grep/find/ls tools; glob handling consumes the same rule
 * catalog through representative candidates.
 */
export function commandReferencesPrivateData(
	command: string,
	cwd: string,
): boolean {
	const expanded = expandHomeReferences(command);
	if (referencesDynamicPiPath(expanded)) return true;

	for (const token of shellEvidenceTokens(expanded)) {
		// `--exclude=.env`, `--exclude-dir=.bundle`: a plain exclusion value never
		// reads. A token carrying whitespace or shell operators (a quoted script
		// passed to eval/sh -c) is still scanned.
		if (/^--(?:exclude|ignore)(?:-dir)?=[^\s;&|<>()`$]*$/i.test(token)) continue;
		for (const candidate of tokenValueCandidates(token)) {
			if (!candidate) continue;
			if (pathPatternReferencesPrivateData(candidate)) return true;
			if (
				looksLikeLiteralPath(candidate) &&
				classifyReadPath(candidate, cwd).private
			) {
				return true;
			}
		}
	}
	return false;
}

export function looksLikePrivateGlob(glob: string): boolean {
	return pathPatternReferencesPrivateData(glob);
}

function expandHomeReferences(value: string): string {
	return value
		.replace(/\$\{HOME\}|\$HOME/gi, homedir())
		.replace(/(^|[\s'"=(])~(?=\/)/g, `$1${homedir()}`);
}

function shellEvidenceTokens(command: string): string[] {
	const tokens: string[] = [];
	let current = "";
	let quote: "'" | '"' | undefined;
	const flush = () => {
		if (current) tokens.push(current);
		current = "";
	};

	for (let index = 0; index < command.length; index++) {
		const character = command[index];
		if (quote === "'") {
			if (character === "'") quote = undefined;
			else current += character;
			continue;
		}
		if (quote === '"') {
			if (character === '"') {
				quote = undefined;
				continue;
			}
			if (
				character === "\\" &&
				index + 1 < command.length &&
				/["$`\\\n]/.test(command[index + 1] ?? "")
			) {
				current += command[++index];
				continue;
			}
			current += character;
			continue;
		}
		if (character === "'" || character === '"') {
			quote = character;
			continue;
		}
		if (/\s/.test(character) || /[;|&<>()]/.test(character)) {
			flush();
			continue;
		}
		if (
			character === "\\" &&
			index + 1 < command.length &&
			/[\s'";|&<>()]/.test(command[index + 1] ?? "")
		) {
			current += command[++index];
			continue;
		}
		current += character;
	}
	flush();
	return tokens;
}

function tokenValueCandidates(token: string): string[] {
	const candidates = [token];
	const equals = token.lastIndexOf("=");
	if (equals >= 0 && equals < token.length - 1) {
		candidates.push(token.slice(equals + 1));
	}
	return candidates.map(cleanShellToken).filter(Boolean);
}

function cleanShellToken(token: string): string {
	return token.replace(/^[,:]+/, "").replace(/,+$/, "").trim();
}

function looksLikeLiteralPath(token: string): boolean {
	return (
		token.startsWith(".") ||
		token.startsWith("/") ||
		token.startsWith("~") ||
		token.startsWith("@") ||
		token.startsWith("file://") ||
		/^[a-z]:[\\/]/i.test(token) ||
		/^\\\\/.test(token) ||
		token.includes("/") ||
		token.includes("\\")
	);
}

function pathPatternReferencesPrivateData(expression: string): boolean {
	// Prose context: multi-line text (quoted multi-line strings) or a single
	// regex argument. There, words such as "credentials" are prose and
	// one-character glob fragments are noise. A regex-looking string that also
	// looks like a script (inner quotes, `;`, `&&`, `$(`, backticks) is never
	// prose, so `bash -c "grep '\s' credentials"` keeps its bare names.
	const scriptLike = /['"`;]|&&|\$\(/.test(expression);
	const prose =
		!scriptLike && (/\n/.test(expression) || looksLikeRegex(expression));
	const words = [...new Set([expression, ...expression.split(/\s+/)])];
	return words.some((word) => wordReferencesPrivateData(word, prose));
}

function wordReferencesPrivateData(word: string, prose: boolean): boolean {
	// Path-shaped words always get the full check: `~/.*/*\s` is a glob that
	// bash reads as `~/.*/*s`, not a regex.
	const pathShaped = startsLikePath(word);
	const regexLike = !pathShaped && looksLikeRegex(word);
	const proseWord = prose && !pathShaped;
	const source = regexLike ? stripRegexEscapes(word) : word;
	const tokens = [source, ...source.split(/[\s'"`;|&<>()]+/)]
		.map((token) => token.slice(token.lastIndexOf("=") + 1))
		.map(cleanShellToken)
		.filter(Boolean);
	return tokens.some((token) => {
		// Negated selectors (`rg -g '!**/.*'`) exclude paths; they never read them.
		if (
			token.startsWith("!") &&
			!/[\s;&|<>()`$]/.test(token) &&
			!token.includes("..")
		) {
			return false;
		}
		if (proseWord && !/[./\\*?[\]{}]/.test(token)) return false;
		const segments = token
			.replace(/\\/g, "/")
			.toLowerCase()
			.split("/")
			.filter(Boolean);
		for (let index = 0; index < segments.length; index++) {
			const pattern = segments[index] ?? "";
			if (isNoiseFragment(pattern, regexLike, proseWord)) continue;
			const extensionGlob = extensionOnlyGlobIsPrivate(pattern);
			if (extensionGlob !== undefined) {
				if (extensionGlob) return true;
				continue;
			}
			if (
				[...PRIVATE_GLOB_DIRECTORY_CANDIDATES, ...PRIVATE_GLOB_FILE_CANDIDATES].some(
					(candidate) => shellGlobMatches(pattern, candidate),
				)
			) {
				return true;
			}
			if (
				index > 0 &&
				shellGlobMatches(segments[index - 1] ?? "", ".config") &&
				PRIVATE_CONFIG_GLOB_DIRECTORY_CANDIDATES.some((candidate) =>
					shellGlobMatches(pattern, candidate),
				)
			) {
				return true;
			}
		}
		return false;
	});
}

function startsLikePath(word: string): boolean {
	return /^(?:\/|~|\.\.?\/|[a-z]:[\\/]|\\\\)/i.test(word);
}

// Escapes that mark a regex. Shell/printf escapes (`\n`, `\t`, `\r`, `\1`)
// are deliberately absent so ordinary inline scripts are not treated as regex.
const REGEX_TRIGGER_ESCAPE = /\\[sSdDwWbB.|()[\]{}+*?^$\/<>]/;
// Escapes removed from a regex before glob matching.
const REGEX_STRIP_ESCAPE = /\\[sSdDwWbBntr.|()[\]{}+*?^$\/<>0-9]/g;

function looksLikeRegex(expression: string): boolean {
	return (
		REGEX_TRIGGER_ESCAPE.test(expression) ||
		/^\^/.test(expression) ||
		/\(\?/.test(expression) ||
		/\[\^/.test(expression) ||
		/\.\*[^/\s*]/.test(expression) ||
		/[^/\s.]\.\*/.test(expression) ||
		/^s([/|#,:@]).*\1.*\1[a-z0-9]*$/i.test(expression)
	);
}

function stripRegexEscapes(expression: string): string {
	return expression.replace(REGEX_STRIP_ESCAPE, " ");
}

function globLiteral(pattern: string): string {
	return pattern.replace(/\[[^\]]*\]/g, "").replace(/[*?{},]/g, "");
}

/**
 * Inside a regex word, `.*`/`.*?` are quantifiers. Inside prose (multi-line
 * text or a regex argument), one-character glob fragments such as `*a` or
 * `1***` are markdown/prose noise. Bare shell words such as `cat .*` or
 * `cat c*`, and single-line scripts such as `bash -c 'cat c*'`, stay private.
 */
function isNoiseFragment(
	pattern: string,
	regexLike: boolean,
	prose: boolean,
): boolean {
	if (!/[*?]/.test(pattern)) return false;
	if (/^\.[*?+]*$/.test(pattern)) return regexLike;
	return prose && globLiteral(pattern).length <= 1;
}

/**
 * Extension-only globs (`*.json`, `--include=*.yaml`, `*.{ts,json}`) describe
 * a file type, not a credential name. They are private only when the
 * extension itself is a private format such as `*.pem` or `*.env`.
 * Returns undefined when the pattern is not an extension-only glob.
 */
function extensionOnlyGlobIsPrivate(pattern: string): boolean | undefined {
	const expanded = expandBracePatterns(pattern);
	const extensions: string[] = [];
	for (const candidate of expanded) {
		const match = /^\*+\.([a-z0-9][a-z0-9_+-]*)\*?$/i.exec(candidate);
		if (!match?.[1]) return undefined;
		extensions.push(match[1]);
	}
	if (extensions.length === 0) return undefined;
	return extensions.some(
		(extension) =>
			isPrivateReadBasename(`file.${extension}`) || extension === "env",
	);
}

function shellGlobMatches(pattern: string, candidate: string): boolean {
	return expandBracePatterns(pattern).some((expanded) => {
		const literal = expanded.replace(/\[[^\]]*\]/g, "").replace(/[*?]/g, "");
		if (literal.length === 0) return false;
		let source = "^";
		for (let index = 0; index < expanded.length; index++) {
			const character = expanded[index];
			if (character === "*") {
				source += ".*";
			} else if (character === "?") {
				source += ".";
			} else if (character === "[") {
				const close = expanded.indexOf("]", index + 1);
				if (close < 0) {
					source += "\\[";
					continue;
				}
				let content = expanded.slice(index + 1, close);
				if (content.startsWith("!")) content = `^${content.slice(1)}`;
				source += `[${content}]`;
				index = close;
			} else {
				source += escapeRegExp(character);
			}
		}
		try {
			return new RegExp(`${source}$`, "i").test(candidate);
		} catch {
			return false;
		}
	});
}

function expandBracePatterns(pattern: string, depth = 0): string[] {
	if (depth >= 2) return [pattern];
	const match = /\{([^{}]+)\}/.exec(pattern);
	if (!match || match.index === undefined) return [pattern];
	const options = match[1].split(",");
	if (options.length === 0 || options.length > 16) return [pattern];
	const prefix = pattern.slice(0, match.index);
	const suffix = pattern.slice(match.index + match[0].length);
	return options.flatMap((option) =>
		expandBracePatterns(`${prefix}${option}${suffix}`, depth + 1),
	);
}

// `.pi` as a real directory segment, not `.pi-agent/`, `tools.pi` or `self.pi_x`.
const PI_SEGMENT = /(?<![\w.-])\.pi(?![\w-])/i;

// Source and installed-package subtrees that docs/REFERENCE.md documents as
// not private solely because they live under `.pi/`.
const PI_PUBLIC_SUBTREE =
	/^\/(?:agent\/)?(?:skills|extensions|prompts|themes|agents|git|npm\/node_modules|context-mode\/insight-cache\/node_modules)\//i;

const SHELL_GLOB = /[*?[\]{}]/;

function isWindowsStyle(token: string): boolean {
	return /^[a-z]:[\\/]/i.test(token) || /^\\\\/.test(token);
}

/**
 * Normalizes one brace expansion the way the shell would see the path:
 * Windows-style tokens use `\` as a separator; elsewhere `\x` is a shell
 * escape for `x` (so `\.pi` is `.pi` and `'^\[tools\.pi\]'` is not a path).
 */
function normalizePiCandidate(token: string): string {
	return isWindowsStyle(token)
		? token.replace(/\\/g, "/")
		: token.replace(/\\(.)/g, "$1");
}

/**
 * True when a glob/variable path under `.pi` may reach private Pi data.
 * Every brace expansion is checked. Only the first `.pi` segment counts, the
 * public-subtree exemption needs a literal prefix, and the remainder may not
 * climb out through `..` or globs that can match it (`.?`, `.[.]`, `[.][.]`
 * in older bash or with dotglob).
 */
function piCandidateIsPrivate(candidate: string): boolean {
	const path = normalizePiCandidate(candidate);
	const match = PI_SEGMENT.exec(path);
	if (!match || match.index === undefined) return false;
	if (!SHELL_GLOB.test(path) && !path.includes("$")) return false;
	if (path.includes("$")) return true;
	const prefix = path.slice(0, match.index);
	const rest = path.slice(match.index + match[0].length);
	const subtree = PI_PUBLIC_SUBTREE.exec(rest);
	if (!subtree || SHELL_GLOB.test(prefix)) return true;
	const tail = rest.slice(subtree[0].length).split("/");
	return tail.some(
		(segment) =>
			segment === ".." ||
			/[{}]/.test(segment) ||
			(SHELL_GLOB.test(segment) &&
				(segment.startsWith(".") || segment.startsWith("["))),
	);
}

function referencesDynamicPiPath(command: string): boolean {
	const tokens = command.split(/[\s'"`;|&<>()]+/).filter(Boolean);
	if (
		tokens.some((token) =>
			expandBracePatterns(token).some(piCandidateIsPrivate),
		)
	) {
		return true;
	}

	const assignments = command.matchAll(
		/(?:^|[;\s])([a-z_][a-z0-9_]*)\s*=\s*["']?([^;\s"']*\.pi[^;\s"']*)/gi,
	);
	for (const assignment of assignments) {
		const variable = assignment[1];
		if (!variable) continue;
		const value = assignment[2] ?? "";
		if (
			!expandBracePatterns(value).some((expanded) =>
				PI_SEGMENT.test(normalizePiCandidate(expanded)),
			)
		) {
			continue;
		}
		const remaining = command.slice(
			(assignment.index ?? 0) + assignment[0].length,
		);
		const variableReference = new RegExp(
			`\\$(?:${escapeRegExp(variable)}\\b|\\{${escapeRegExp(variable)}\\})`,
		);
		if (variableReference.test(remaining)) return true;
	}
	return false;
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
