import type {
	IDataObject,
	IExecuteFunctions,
	IHttpRequestMethods,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';
import { verifyReceipt } from './verify';

function parseJsonParam(ctx: IExecuteFunctions, value: unknown, what: string, itemIndex: number): unknown {
	if (typeof value !== 'string') return value;
	const s = value.trim();
	if (!s) return undefined;
	try {
		return JSON.parse(s);
	} catch {
		throw new NodeOperationError(ctx.getNode(), `${what} is not valid JSON`, { itemIndex });
	}
}

function toMessages(ctx: IExecuteFunctions, value: unknown, itemIndex: number): IDataObject[] {
	if (Array.isArray(value)) return value as IDataObject[];
	if (typeof value === 'string') {
		const s = value.trim();
		if (!s) return [];
		if (s.startsWith('[')) return parseJsonParam(ctx, s, 'Prompt', itemIndex) as IDataObject[];
		return [{ role: 'user', content: s }];
	}
	throw new NodeOperationError(ctx.getNode(), 'Prompt must be text or a JSON array of {role, content}', { itemIndex });
}

export class Idemcore implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Idemcore',
		name: 'idemcore',
		icon: { light: 'file:../../icons/idemcore.svg', dark: 'file:../../icons/idemcore.dark.svg' },
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Get AI answers with a signed receipt, and check receipts offline',
		defaults: { name: 'Idemcore' },
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		usableAsTool: true,
		credentials: [
			{
				name: 'idemcoreApi',
				required: true,
				displayOptions: { show: { operation: ['chat'] } },
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Chat',
						value: 'chat',
						action: 'Chat and return a signed receipt',
						description: 'Send a chat request and get the answer with its signed receipt',
					},
					{
						name: 'Verify Receipt',
						value: 'verify',
						action: 'Verify a receipt offline',
						description: 'Check a signed receipt locally. Free, no API key, no network call.',
					},
				],
				default: 'chat',
			},
			{
				displayName: 'Prompt',
				name: 'prompt',
				type: 'string',
				typeOptions: { rows: 4 },
				default: '',
				required: true,
				displayOptions: { show: { operation: ['chat'] } },
				description: 'The user message. Use a JSON array of {role, content} objects to send several messages.',
			},
			{
				displayName: 'Model',
				name: 'model',
				type: 'string',
				default: '',
				displayOptions: { show: { operation: ['chat'] } },
				description: 'Model ID. Leave empty to use the account default.',
			},
			{
				displayName: 'Max Tokens',
				name: 'maxTokens',
				type: 'number',
				default: 512,
				typeOptions: { minValue: 1, maxValue: 2048 },
				displayOptions: { show: { operation: ['chat'] } },
				description: 'Maximum number of tokens in the answer',
			},
			{
				displayName: 'Privacy',
				name: 'privacy',
				type: 'options',
				options: [
					{ name: 'Hash Only', value: 'hash_only', description: 'The receipt stores only salted hashes of the prompt and answer' },
					{ name: 'Full', value: 'full', description: 'The prompt and answer are stored with the receipt' },
				],
				default: 'hash_only',
				displayOptions: { show: { operation: ['chat'] } },
			},
			{
				displayName: 'Receipt',
				name: 'receipt',
				type: 'json',
				default: '{}',
				required: true,
				displayOptions: { show: { operation: ['verify'] } },
				description: 'The signed receipt JSON, or an object that has a "receipt" field (for example the output of the Chat operation)',
			},
			{
				displayName: 'Options',
				name: 'verifyOptions',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				displayOptions: { show: { operation: ['verify'] } },
				options: [
					{
						displayName: 'Answer Text',
						name: 'outputText',
						type: 'string',
						typeOptions: { rows: 3 },
						default: '',
						description: 'Check that this displayed answer matches the receipt (needs Salt for hash-only receipts)',
					},
					{
						displayName: 'Public Token Log',
						name: 'logText',
						type: 'string',
						typeOptions: { rows: 5 },
						default: '',
						description: 'Public token log for the receipt, to also check the token chain',
					},
					{
						displayName: 'Salt',
						name: 'salt',
						type: 'string',
						typeOptions: { password: true },
						default: '',
						description: 'Disclosure salt returned with a hash-only Chat answer',
					},
					{
						displayName: 'Trusted Keys (JWKS)',
						name: 'keys',
						type: 'json',
						default: '',
						description: 'Optional JWK or JWKS of trusted signing keys. Default: the bundled Idemcore production public key.',
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const out: INodeExecutionData[] = [];

		for (let i = 0; i < items.length; i++) {
			try {
				const operation = this.getNodeParameter('operation', i) as string;
				if (operation === 'chat') {
					const credentials = await this.getCredentials('idemcoreApi');
					const baseUrl = String(credentials.baseUrl || 'https://api.idemcore.net')
						.replace(/\/+$/, '')
						.replace(/\/v1$/, '');
					const messages = toMessages(this, this.getNodeParameter('prompt', i), i);
					if (!messages.length) throw new NodeOperationError(this.getNode(), 'Prompt is empty', { itemIndex: i });
					const body: IDataObject = {
						messages,
						max_tokens: this.getNodeParameter('maxTokens', i) as number,
						idemcore: { privacy: this.getNodeParameter('privacy', i) as string },
					};
					const model = this.getNodeParameter('model', i) as string;
					if (model) body.model = model;
					const d = (await this.helpers.httpRequestWithAuthentication.call(this, 'idemcoreApi', {
						method: 'POST' as IHttpRequestMethods,
						url: `${baseUrl}/v1/chat/completions`,
						body,
						json: true,
					})) as IDataObject;
					const choice = ((d.choices as IDataObject[]) || [])[0] || {};
					const idem = (d.idemcore as IDataObject) || {};
					const receipt = (d.idemcore_receipt || idem.receipt) as IDataObject | undefined;
					if (!receipt || typeof receipt.receipt_id !== 'string') {
						throw new NodeOperationError(this.getNode(), 'The response carried no receipt', { itemIndex: i });
					}
					const disclosure = (idem.disclosure as IDataObject) || {};
					out.push({
						json: {
							text: ((choice.message as IDataObject) || {}).content ?? '',
							receipt_id: receipt.receipt_id,
							receipt,
							model: d.model,
							finish_reason: choice.finish_reason ?? null,
							usage: d.usage ?? null,
							privacy: receipt.privacy,
							salt: d.idemcore_salt ?? disclosure.salt ?? null,
						},
						pairedItem: { item: i },
					});
				} else {
					const raw = parseJsonParam(this, this.getNodeParameter('receipt', i), 'Receipt', i) as IDataObject;
					const receipt = (raw && typeof raw === 'object' && raw.receipt ? raw.receipt : raw) as IDataObject;
					const o = this.getNodeParameter('verifyOptions', i, {}) as IDataObject;
					const keys = o.keys ? parseJsonParam(this, o.keys, 'Trusted Keys', i) : undefined;
					const logText = (o.logText as string) || (raw && typeof raw.log_text === 'string' ? raw.log_text : undefined);
					const verification = await verifyReceipt(receipt, {
						keys,
						logText: logText || undefined,
						outputText: (o.outputText as string) || undefined,
						salt: (o.salt as string) || undefined,
					});
					const errors = Object.values(verification.levels).flatMap((l) => l.errors);
					out.push({
						json: {
							ok: verification.ok,
							verdict: verification.ok ? 'VERIFIED' : 'FAILED',
							receipt_id: receipt?.receipt_id ?? null,
							model: receipt?.model_id ?? null,
							key_id: receipt?.key_id ?? null,
							issued_at: receipt?.issued_at ?? null,
							errors,
							levels: verification.levels as unknown as IDataObject,
						},
						pairedItem: { item: i },
					});
				}
			} catch (error) {
				if (this.continueOnFail()) {
					out.push({ json: { error: (error as Error).message }, pairedItem: { item: i } });
					continue;
				}
				throw new NodeOperationError(this.getNode(), error as Error, { itemIndex: i });
			}
		}
		return [out];
	}
}
