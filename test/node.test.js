const test = require('node:test');
const assert = require('node:assert');
const vec = require('./fixtures/vectors_r2.json');
const { Idemcore } = require('../dist/nodes/Idemcore/Idemcore.node.js');
const { verifyReceipt } = require('../dist/nodes/Idemcore/verify.js');

function ctx(params, http) {
	return {
		getInputData: () => [{ json: {} }],
		getNodeParameter: (name, _i, fallback) => (name in params ? params[name] : fallback),
		getCredentials: async () => ({ apiKey: 'test', baseUrl: 'https://api.example.test/' }),
		getNode: () => ({ name: 'Idemcore', type: 'idemcore', typeVersion: 1, parameters: {} }),
		continueOnFail: () => false,
		helpers: { httpRequestWithAuthentication: http },
	};
}

test('verifies the public r2 test vector with its test key', async () => {
	const r = await verifyReceipt(vec.receipt, { keys: [vec.public_jwk] });
	assert.equal(r.ok, true, JSON.stringify(r));
});

test('rejects a tampered receipt', async () => {
	const r = await verifyReceipt({ ...vec.receipt, model_id: 'other' }, { keys: [vec.public_jwk] });
	assert.equal(r.ok, false);
	assert.match(r.levels.L1.errors[0], /signature/);
});

test('test-key receipt is not trusted by the bundled production key', async () => {
	const r = await verifyReceipt(vec.receipt);
	assert.equal(r.ok, false);
	assert.match(r.levels.L1.errors[0], /unknown key_id/);
});

test('node Verify Receipt operation', async () => {
	const node = new Idemcore();
	const out = await node.execute.call(
		ctx({
			operation: 'verify',
			receipt: JSON.stringify({ receipt: vec.receipt }),
			verifyOptions: { keys: JSON.stringify(vec.public_jwk) },
		}),
	);
	assert.equal(out[0][0].json.ok, true);
	assert.equal(out[0][0].json.verdict, 'VERIFIED');
});

test('node Chat operation maps the response', async () => {
	let seen;
	const http = async function (cred, opts) {
		seen = { cred, opts };
		return {
			model: 'm',
			choices: [{ message: { content: 'hi' }, finish_reason: 'stop' }],
			usage: { total_tokens: 3 },
			idemcore_receipt: vec.receipt,
			idemcore_salt: 'c2FsdA',
		};
	};
	const node = new Idemcore();
	const out = await node.execute.call(
		ctx({ operation: 'chat', prompt: 'Hello', model: '', maxTokens: 16, privacy: 'hash_only' }, http),
	);
	assert.equal(seen.cred, 'idemcoreApi');
	assert.equal(seen.opts.url, 'https://api.example.test/v1/chat/completions');
	assert.deepEqual(seen.opts.body.messages, [{ role: 'user', content: 'Hello' }]);
	assert.equal(out[0][0].json.text, 'hi');
	assert.equal(out[0][0].json.receipt_id, vec.receipt.receipt_id);
});
