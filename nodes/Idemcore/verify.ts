// Offline verification of Idemcore receipts (formats r1 and r2).
// Self-contained port of the verifier in the public Idemcore JavaScript SDK
// (https://github.com/idemcore/idemcore-js), so this package has no runtime dependencies.
// Uses only the standard WebCrypto API (Ed25519, SHA-256).

/* eslint-disable @typescript-eslint/no-explicit-any */

type Bytes = Uint8Array;

export interface LevelResult {
	level: string;
	ok: boolean;
	errors: string[];
	[key: string]: unknown;
}

export interface VerifyResult {
	ok: boolean;
	levels: Record<string, LevelResult>;
}

interface TrustedKey {
	keyId: string;
	source: string;
	verify: (sig: Bytes, msg: Bytes) => Promise<boolean>;
}

/** Idemcore production receipt-signing public key (public half only). Live set: GET https://api.idemcore.net/v1/keys */
export const DEFAULT_TRUSTED_KEYS = [
	{
		kty: 'OKP',
		crv: 'Ed25519',
		x: 'AdQX-eipjpmqi4GDvqYHIep2Vb7l5Vas4xncNN453OY',
		kid: 'ed25519:2fab59995ac55e4f',
	},
];

const te = new TextEncoder();
const utf8 = (s: string): Bytes => te.encode(s);

function hex(b: Bytes): string {
	let s = '';
	for (const x of b) s += x.toString(16).padStart(2, '0');
	return s;
}

function concat(...parts: Bytes[]): Bytes {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
	let o = 0;
	for (const p of parts) {
		out.set(p, o);
		o += p.length;
	}
	return out;
}

const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const REV: Record<string, number> = Object.fromEntries([...ALPHA].map((c, i) => [c, i]));

function b64uDecode(s: unknown): Bytes {
	if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
		throw new Error('not base64url');
	}
	const out = new Uint8Array(Math.floor((s.length * 3) / 4));
	let o = 0;
	for (let i = 0; i < s.length; i += 4) {
		const c = [0, 1, 2, 3].map((k) => (i + k < s.length ? REV[s[i + k]] : 0));
		const n = (c[0] << 18) | (c[1] << 12) | (c[2] << 6) | c[3];
		out[o++] = (n >> 16) & 255;
		if (i + 2 < s.length) out[o++] = (n >> 8) & 255;
		if (i + 3 < s.length) out[o++] = n & 255;
	}
	return out.slice(0, o);
}

declare const crypto: any;

function subtle(): any {
	const c = typeof crypto === 'undefined' ? undefined : crypto;
	if (!c || !c.subtle) throw new Error('WebCrypto is not available (n8n on Node.js 20 or newer is required)');
	return c.subtle;
}

async function sha256(data: Bytes): Promise<Bytes> {
	return new Uint8Array(await subtle().digest('SHA-256', data));
}

function le64(n: bigint): Bytes {
	const b = new Uint8Array(8);
	new DataView(b.buffer).setBigUint64(0, BigInt.asUintN(64, n), true);
	return b;
}

// Canonical JSON: keys sorted by code point, no whitespace, integers only.
function cmp(a: string, b: string): number {
	const A = Array.from(a);
	const B = Array.from(b);
	for (let i = 0; i < Math.min(A.length, B.length); i++) {
		const d = (A[i].codePointAt(0) as number) - (B[i].codePointAt(0) as number);
		if (d) return d;
	}
	return A.length - B.length;
}

function enc(v: unknown, path: string): string {
	if (v === null) return 'null';
	if (typeof v === 'boolean') return v ? 'true' : 'false';
	if (typeof v === 'string') return JSON.stringify(v);
	if (typeof v === 'number') {
		if (!Number.isSafeInteger(v)) throw new Error(`${path}: only integers are allowed`);
		return String(v);
	}
	if (Array.isArray(v)) return '[' + v.map((x, i) => enc(x, `${path}[${i}]`)).join(',') + ']';
	if (typeof v === 'object') {
		const o = v as Record<string, unknown>;
		const keys = Object.keys(o)
			.filter((k) => o[k] !== undefined)
			.sort(cmp);
		return '{' + keys.map((k) => JSON.stringify(k) + ':' + enc(o[k], `${path}.${k}`)).join(',') + '}';
	}
	throw new Error(`${path}: unsupported type`);
}

const canonicalString = (v: unknown): string => enc(v, '$');
const canonicalBytes = (v: unknown): Bytes => te.encode(canonicalString(v));

async function keyIdFor(raw: Bytes): Promise<string> {
	return 'ed25519:' + hex((await sha256(raw)).slice(0, 8));
}

async function importJwk(jwk: any, source: string): Promise<TrustedKey> {
	if (jwk?.kty !== 'OKP' || jwk?.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
		throw new Error('not an Ed25519 public JWK');
	}
	const raw = b64uDecode(jwk.x);
	if (raw.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
	const keyId = await keyIdFor(raw);
	if (jwk.kid && jwk.kid !== keyId) throw new Error(`kid ${jwk.kid} does not match key bytes (${keyId})`);
	const pk = await subtle().importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
	return {
		keyId,
		source,
		verify: async (sig: Bytes, msg: Bytes) => {
			try {
				return await subtle().verify({ name: 'Ed25519' }, pk, sig, msg);
			} catch {
				return false;
			}
		},
	};
}

async function importKeySet(data: any, source: string): Promise<TrustedKey[]> {
	const list = Array.isArray(data)
		? data
		: data && typeof data === 'object' && Array.isArray(data.keys)
			? data.keys
			: [data];
	return Promise.all(list.map((j: any) => importJwk(j, source)));
}

// Hashes and token-log chain digests.
async function taggedHash(tag: string, ...parts: Bytes[]): Promise<string> {
	const chunks: Bytes[] = [utf8(`idemcore/${tag}/r1`), new Uint8Array([0])];
	for (const p of parts) chunks.push(le64(BigInt(p.length)), p);
	return hex(await sha256(concat(...chunks)));
}

function tokenBytes(ids: number[]): Bytes {
	const b = new Uint8Array(ids.length * 4);
	const dv = new DataView(b.buffer);
	ids.forEach((id, i) => {
		if (!Number.isInteger(id) || id < 0 || id > 0xffffffff) throw new Error(`token id out of range at ${i}`);
		dv.setUint32(i * 4, id, true);
	});
	return b;
}

const promptHash = (messages: unknown, salt: Bytes) => taggedHash('prompt', salt, canonicalBytes(messages));
const tokenHash = (ids: number[], salt: Bytes) => taggedHash('tokens', salt, tokenBytes(ids));
const WS = /[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/g;
const normalizeText = (s: string) => s.normalize('NFC').replace(WS, ' ').replace(/^ | $/g, '');
const textHash = (text: string, salt: Bytes) => taggedHash('text', salt, utf8(normalizeText(text)));

interface LogLine {
	pi: bigint;
	j: bigint;
	h: bigint;
	hc: bigint;
}

function parseLog(text: string): { lines: LogLine[]; all: string | null } {
	const lines: LogLine[] = [];
	let all: string | null = null;
	text.split(/\r?\n/).forEach((raw, n) => {
		const s = raw.trim();
		if (!s || s.startsWith('#')) return;
		const f = s.split(/\s+/);
		if (f[0] === 'ALL') {
			if (f.length !== 2 || !/^[0-9a-fA-F]{1,16}$/.test(f[1])) throw new Error(`log line ${n + 1}: malformed ALL line`);
			all = f[1].toLowerCase();
			return;
		}
		if (!/^\d+$/.test(f[0])) return;
		if (f.length !== 4) throw new Error(`log line ${n + 1}: not a public log line (expected 4 fields: pi j h hc)`);
		if (!/^\d+$/.test(f[1]) || !/^[0-9a-fA-F]{1,16}$/.test(f[2]) || !/^[0-9a-fA-F]{1,16}$/.test(f[3])) {
			throw new Error(`log line ${n + 1}: malformed field`);
		}
		const ln = { pi: BigInt(f[0]), j: BigInt(f[1]), h: BigInt('0x' + f[2]), hc: BigInt('0x' + f[3]) };
		if (ln.pi >= BigInt(2) ** BigInt(64) || ln.j >= BigInt(2) ** BigInt(64)) {
			throw new Error(`log line ${n + 1}: index out of range`);
		}
		lines.push(ln);
	});
	return { lines, all };
}

const FNV_OFFSET = BigInt('0xcbf29ce484222325');
const FNV_PRIME = BigInt('0x100000001b3');
const MASK = (BigInt(1) << BigInt(64)) - BigInt(1);

function fnv(data: Bytes, start: bigint): bigint {
	let h = start;
	for (const b of data) h = ((h ^ BigInt(b)) * FNV_PRIME) & MASK;
	return h;
}

function chainFnv(lines: LogLine[]): string {
	let a = FNV_OFFSET;
	for (const l of lines) {
		a = fnv(le64(l.h), a);
		a = fnv(le64(l.hc), a);
	}
	return a.toString(16).padStart(16, '0');
}

async function chainDigest(lines: LogLine[]): Promise<string> {
	let c = await sha256(utf8('idemcore/chain/r1\0'));
	for (const l of lines) c = await sha256(concat(c, le64(l.pi), le64(l.j), le64(l.h), le64(l.hc)));
	return hex(c);
}

// Receipt checks.
const RECEIPT_VERSIONS = ['r1', 'r2'];
const R2_RENAMES: Record<string, string> = { seed: 'variant', chain_fnv: 'chain_check', kernel_version: 'engine_version' };
const SIG_DOMAIN = utf8('idemcore-receipt/r1\n');
const HEX64 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{16}$/;
const REQUIRED_R1: Record<string, string> = {
	receipt_version: 'str', receipt_id: 'str', issued_at: 'str', tenant_id: 'str', model_id: 'str',
	weights_hash: 'str', kernel_version: 'str', engine_build: 'str', privacy: 'str', prompt_hash: 'str',
	params_hash: 'str', seed: 'int', decoding: 'str', prompt_tokens: 'int', output_tokens: 'int',
	output_token_hash: 'str', chain_digest: 'str', chain_fnv: 'str', log_ref: 'str', key_id: 'str', signature: 'str',
};
const REQUIRED_R2: Record<string, string> = Object.fromEntries(
	Object.entries(REQUIRED_R1).map(([k, t]) => [R2_RENAMES[k] ?? k, t]),
);
const OPTIONAL: Record<string, string> = { finish_reason: 'str', request_id: 'str', output_text_hash: 'str' };
const HASH_FIELDS = ['weights_hash', 'prompt_hash', 'params_hash', 'output_token_hash', 'chain_digest'];
const chainCheckField = (r: any) => (r.receipt_version === 'r2' ? 'chain_check' : 'chain_fnv');

const result = (level: string, errors: string[], extra: Record<string, unknown> = {}): LevelResult => ({
	level,
	ok: errors.length === 0,
	errors,
	...extra,
});

function signingPayload(r: Record<string, unknown>): Bytes {
	const body = { ...r };
	delete body.signature;
	return concat(SIG_DOMAIN, canonicalBytes(body));
}

function checkFormat(r: unknown): string[] {
	if (typeof r !== 'object' || r === null || Array.isArray(r)) return ['receipt is not an object'];
	const o = r as Record<string, any>;
	const errs: string[] = [];
	if (!RECEIPT_VERSIONS.includes(o.receipt_version)) return [`unsupported receipt_version ${String(o.receipt_version)}`];
	const REQUIRED = o.receipt_version === 'r2' ? REQUIRED_R2 : REQUIRED_R1;
	const CHK = chainCheckField(o);
	for (const [k, t] of Object.entries(REQUIRED)) {
		if (!(k in o)) errs.push(`missing field ${k}`);
		else if (t === 'int' ? !Number.isSafeInteger(o[k]) : typeof o[k] !== 'string') errs.push(`field ${k} must be ${t}`);
	}
	for (const k of Object.keys(o)) if (!(k in REQUIRED) && !(k in OPTIONAL)) errs.push(`unknown field ${k}`);
	for (const k of Object.keys(OPTIONAL)) if (k in o && typeof o[k] !== 'string') errs.push(`field ${k} must be str`);
	if (errs.length) return errs;
	for (const k of HASH_FIELDS) if (!HEX64.test(o[k])) errs.push(`${k} must be 64 lowercase hex`);
	if ('output_text_hash' in o && !HEX64.test(o.output_text_hash)) errs.push('output_text_hash must be 64 lowercase hex');
	if (!HEX16.test(o[CHK])) errs.push(`${CHK} must be 16 lowercase hex`);
	if (o.privacy !== 'hash_only' && o.privacy !== 'full') errs.push('privacy must be hash_only or full');
	if (o.prompt_tokens < 1 || o.output_tokens < 0) errs.push('token counts out of range');
	if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?Z$/.test(o.issued_at)) errs.push('issued_at must be RFC 3339 UTC (Z)');
	try {
		canonicalString(o);
	} catch (e) {
		errs.push((e as Error).message);
	}
	return errs;
}

async function verifyL1(r: any, keys: TrustedKey[]): Promise<LevelResult> {
	const errs = checkFormat(r);
	if (errs.length) return result('L1', errs);
	const pk = keys.find((k) => k.keyId === r.key_id);
	if (!pk) return result('L1', [`unknown key_id ${String(r.key_id)} (not in the trusted key set)`]);
	let sig: Bytes;
	try {
		sig = b64uDecode(r.signature);
	} catch {
		return result('L1', ['signature is not base64url']);
	}
	if (sig.length !== 64 || !(await pk.verify(sig, signingPayload(r)))) return result('L1', ['signature does not verify']);
	return result('L1', [], { key_id: pk.keyId, key_source: pk.source });
}

async function verifyL2(r: any, logText: string): Promise<LevelResult> {
	let d: { positions: number; chain_digest: string; chain_fnv: string; all_line: string | null };
	try {
		const p = parseLog(logText);
		d = { positions: p.lines.length, chain_digest: await chainDigest(p.lines), chain_fnv: chainFnv(p.lines), all_line: p.all };
	} catch (e) {
		return result('L2', [`log parse error: ${(e as Error).message}`]);
	}
	const errs: string[] = [];
	if (d.chain_digest !== r.chain_digest) errs.push('chain_digest mismatch');
	const CHK = chainCheckField(r);
	if (d.chain_fnv !== r[CHK]) errs.push(`${CHK} mismatch`);
	if (d.all_line !== null && d.all_line !== d.chain_fnv) errs.push('log ALL line inconsistent with its own lines');
	const want = Number(r.prompt_tokens ?? 0) + Number(r.output_tokens ?? 0);
	if (d.positions !== want) errs.push(`log covers ${d.positions} positions, receipt says ${want}`);
	return result('L2', errs, { positions: d.positions });
}

async function verifyDisclosure(
	r: any,
	d: { messages?: unknown; outputIds?: number[]; outputText?: string; salt?: Bytes },
): Promise<LevelResult> {
	const salt = r.privacy === 'full' ? new Uint8Array(0) : d.salt;
	if (salt == null) return result('disclosure', ['salt required for hash_only receipts']);
	const errs: string[] = [];
	const checked: string[] = [];
	if (d.messages !== undefined) {
		checked.push('prompt_hash');
		if ((await promptHash(d.messages, salt)) !== r.prompt_hash) errs.push('prompt_hash mismatch');
	}
	if (d.outputIds !== undefined) {
		checked.push('output_token_hash');
		if ((await tokenHash(d.outputIds, salt)) !== r.output_token_hash) errs.push('output_token_hash mismatch');
	}
	if (d.outputText !== undefined) {
		if (typeof r.output_text_hash !== 'string') {
			errs.push('receipt has no output_text_hash; displayed text cannot be bound (use output token ids instead)');
		} else {
			checked.push('output_text_hash');
			if ((await textHash(d.outputText, salt)) !== r.output_text_hash) errs.push('output_text_hash mismatch');
		}
	}
	return result('disclosure', errs, { checked });
}

export interface VerifyOptions {
	keys?: unknown;
	logText?: string;
	messages?: unknown;
	outputText?: string;
	salt?: string;
}

/** Verify a receipt offline: L1 signature, optional L2 token-log chain, optional disclosure. */
export async function verifyReceipt(receipt: unknown, opts: VerifyOptions = {}): Promise<VerifyResult> {
	const levels: Record<string, LevelResult> = {};
	const keys = await importKeySet(opts.keys ?? DEFAULT_TRUSTED_KEYS, opts.keys ? 'caller' : 'bundled');
	levels.L1 = await verifyL1(receipt, keys);
	if (opts.logText !== undefined) levels.L2 = await verifyL2(receipt, opts.logText);
	if (opts.messages !== undefined || opts.outputText !== undefined) {
		let salt: Bytes | undefined;
		try {
			salt = typeof opts.salt === 'string' && opts.salt ? b64uDecode(opts.salt) : undefined;
		} catch {
			levels.disclosure = { level: 'disclosure', ok: false, errors: ['salt is not base64url'] };
		}
		if (!levels.disclosure) {
			levels.disclosure = await verifyDisclosure(receipt, {
				messages: opts.messages,
				outputText: opts.outputText,
				salt,
			});
		}
	}
	const vals = Object.values(levels);
	return { ok: vals.length > 0 && vals.every((l) => l.ok), levels };
}
