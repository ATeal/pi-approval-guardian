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
		// `--exclude=.env`, `--exclude-dir=.bundle`: exclusions never read.
		if (/^--(?:exclude(?:-dir)?|ignore(?:-dir)?)=/i.test(token)) continue;
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
	// Regex and multi-word arguments (grep/sed patterns, inline scripts, prose)
	// are still scanned for private names, but regex escapes and quantifier
	// fragments such as `\s*` or `.*` are not shell globs and must not match
	// arbitrary credential candidates.
	const regexLike = looksLikeRegex(expression);
	const freeText = regexLike || /\s/.test(expression);
	// Regexes and multi-line text (heredoc bodies, inline scripts) mention
	// words like "credentials" or "secret" as prose; there only path-shaped
	// tokens count. Single-line multi-word shell strings keep bare names.
	const proseLike = regexLike || /\n/.test(expression);
	const source = regexLike ? stripRegexEscapes(expression) : expression;
	const tokens = [source, ...source.split(/[\s'"`;|&<>()]+/)]
		.map((token) => token.slice(token.lastIndexOf("=") + 1))
		.map(cleanShellToken)
		.filter(Boolean);
	return tokens.some((token) => {
		// Negated selectors (`rg -g '!**/.*'`) exclude paths; they never read them.
		if (token.startsWith("!")) return false;
		if (proseLike && !/[./\\*?[\]{}]/.test(token)) return false;
		const segments = token
			.replace(/\\/g, "/")
			.toLowerCase()
			.split("/")
			.filter(Boolean);
		for (let index = 0; index < segments.length; index++) {
			const pattern = segments[index] ?? "";
			if (freeText && isQuantifierFragment(pattern, regexLike)) continue;
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

const REGEX_ESCAPE = /\\[sSdDwWbBntr.|()[\]{}+*?^$\/<>0-9]/;

function looksLikeRegex(expression: string): boolean {
	return (
		REGEX_ESCAPE.test(expression) ||
		/^\^/.test(expression) ||
		/\(\?/.test(expression) ||
		/\[\^/.test(expression) ||
		/\.\*[^/\s*]/.test(expression) ||
		/[^/\s.]\.\*/.test(expression) ||
		/^s([/|#,:@]).*\1.*\1[a-z0-9]*$/i.test(expression)
	);
}

function stripRegexEscapes(expression: string): string {
	return expression.replace(new RegExp(REGEX_ESCAPE.source, "g"), " ");
}

function globLiteral(pattern: string): string {
	return pattern.replace(/\[[^\]]*\]/g, "").replace(/[*?{},]/g, "");
}

/**
 * Inside regex or free-text arguments, `.*`/`.*?` are quantifiers and
 * single-character fragments like `*a` or `1***` are prose/markdown noise.
 * A bare shell word such as `cat .*` is never free text and stays private.
 */
function isQuantifierFragment(pattern: string, regexLike: boolean): boolean {
	if (!/[*?]/.test(pattern)) return false;
	const literal = globLiteral(pattern);
	if (/^\.[*?+]*$/.test(pattern)) return regexLike;
	return literal.length <= 1;
}

/**
 * Extension-only globs (`*.json`, `--include=*.yaml`, `*.{ts,json}`) describe
 * a file type, not a credential name. They are private only when the
 * extension itself is a private-key/secret format such as `*.pem`.
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
			isPrivateReadBasename(`file.${extension}`) ||
			extension === "env" ||
			extension === "secret" ||
			extension === "secrets",
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
const PI_DIRECTORY_SEGMENT = /(?:^|[/\\$}~*?])\.pi(?=[/\\*?{}[\]$"']|$)/i;

// Source and installed-package subtrees that docs/REFERENCE.md documents as
// not private solely because they live under `.pi/`.
const PI_PUBLIC_SUBTREE =
	/(?:^|[/\\])\.pi[/\\](?:agent[/\\])?(?:skills|extensions|prompts|themes|agents|git|npm[/\\]node_modules|context-mode[/\\]insight-cache[/\\]node_modules)[/\\]/i;

function referencesDynamicPiPath(command: string): boolean {
	const piTokens = command
		.split(/[\s'"`;|&<>()]+/)
		.filter(
			(token) =>
				PI_DIRECTORY_SEGMENT.test(token) &&
				!/^\^|\\[[(|]|\(\?/.test(token),
		);
	if (
		piTokens.some(
			(token) =>
				/[*?\[\]{}$]/.test(token) &&
				!(
					PI_PUBLIC_SUBTREE.test(token) &&
					!token.includes("$") &&
					!token.includes("..")
				),
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
		if (!PI_DIRECTORY_SEGMENT.test(assignment[2] ?? "")) continue;
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
