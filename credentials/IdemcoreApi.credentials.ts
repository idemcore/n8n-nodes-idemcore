import type {
	IAuthenticateGeneric,
	Icon,
	ICredentialTestRequest,
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class IdemcoreApi implements ICredentialType {
	name = 'idemcoreApi';

	displayName = 'Idemcore API';

	icon: Icon = { light: 'file:../icons/idemcore.svg', dark: 'file:../icons/idemcore.dark.svg' };

	documentationUrl = 'https://idemcore.net/integrations/n8n';

	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			required: true,
			default: '',
			description: 'Your Idemcore API key from idemcore.net. Only the Chat operation uses it; Verify Receipt runs offline.',
		},
		{
			displayName: 'Base URL',
			name: 'baseUrl',
			type: 'string',
			default: 'https://api.idemcore.net',
			description: 'API base URL. Leave the default unless you run a self-hosted Idemcore gateway.',
		},
	];

	authenticate: IAuthenticateGeneric = {
		type: 'generic',
		properties: {
			headers: {
				Authorization: '=Bearer {{$credentials.apiKey}}',
			},
		},
	};

	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.baseUrl.replace(/\\/+$/, "")}}',
			url: '/v1/models',
			method: 'GET',
		},
	};
}
