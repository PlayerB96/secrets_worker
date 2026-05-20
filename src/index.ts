interface SecretsEnv {
	SECRETS_KV?: KVNamespace;
	[key: string]: unknown;
}

const RESERVED_SECRET_NAMES = new Set(['MASTER_KEY']);

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL(request.url);
		const secrets = env as SecretsEnv;

		const readString = (key: string): string | undefined => {
			const value = secrets[key];
			return typeof value === 'string' ? value : undefined;
		};

		const resolveSecretKey = (rawName: string): string | undefined => {
			const inputName = rawName.trim();
			if (!inputName) return undefined;

			if (Object.prototype.hasOwnProperty.call(secrets, inputName) && typeof secrets[inputName] === 'string') {
				return inputName;
			}

			const lowerName = inputName.toLowerCase();
			for (const key of Object.keys(secrets)) {
				if (key.toLowerCase() === lowerName && typeof secrets[key] === 'string') {
					return key;
				}
			}

			return undefined;
		};

		const validateMasterKey = (masterKey: string | undefined): Response | null => {
			const trimmed = masterKey?.trim();
			if (!trimmed) {
				return new Response('Master Key requerida', { status: 400 });
			}

			const expectedMasterKey = readString('MASTER_KEY');
			if (!expectedMasterKey) {
				return new Response('MASTER_KEY no configurada en el Worker', { status: 500 });
			}

			if (trimmed !== expectedMasterKey) {
				return new Response('Master Key incorrecta', { status: 403 });
			}

			return null;
		};

		const normalizeSecretName = (rawName: string): string | undefined => {
			const trimmed = rawName.trim();
			if (!trimmed || RESERVED_SECRET_NAMES.has(trimmed.toUpperCase())) {
				return undefined;
			}
			return trimmed;
		};

		const readKvSecret = async (secretName: string): Promise<string | null> => {
			if (!secrets.SECRETS_KV) return null;
			return secrets.SECRETS_KV.get(secretName);
		};

		const collectEnvSecretNames = (): string[] => {
			const names: string[] = [];
			for (const key of Object.keys(secrets)) {
				if (key === 'SECRETS_KV' || RESERVED_SECRET_NAMES.has(key.toUpperCase())) {
					continue;
				}
				if (typeof secrets[key] === 'string') {
					names.push(key);
				}
			}
			return names;
		};

		const collectKvSecretNames = async (): Promise<string[]> => {
			if (!secrets.SECRETS_KV) return [];

			const names: string[] = [];
			let cursor: string | undefined;

			do {
				const page = await secrets.SECRETS_KV.list({ cursor });
				for (const entry of page.keys) {
					names.push(entry.name);
				}
				cursor = page.list_complete ? undefined : page.cursor;
			} while (cursor);

			return names;
		};

		const collectAllSecretNames = async (): Promise<string[]> => {
			const unique = new Set([...collectEnvSecretNames(), ...(await collectKvSecretNames())]);
			return [...unique].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
		};

		if (url.pathname === '/verify-master-key' && request.method === 'POST') {
			try {
				const data = (await request.json()) as { masterKey?: string };
				const authError = validateMasterKey(data.masterKey);
				if (authError) return authError;

				return new Response('Master Key valida', { status: 200 });
			} catch {
				return new Response('Error procesando request', { status: 400 });
			}
		}

		if (url.pathname === '/add-secret' && request.method === 'POST') {
			try {
				const data = (await request.json()) as {
					masterKey?: string;
					secretName?: string;
					secretValue?: string;
				};

				const authError = validateMasterKey(data.masterKey);
				if (authError) return authError;

				if (!secrets.SECRETS_KV) {
					return new Response('Almacen KV no configurado en el Worker', { status: 500 });
				}

				const secretName = normalizeSecretName(data.secretName ?? '');
				if (!secretName) {
					return new Response('Nombre de secret invalido o reservado', { status: 400 });
				}

				const secretValue = data.secretValue?.trim();
				if (!secretValue) {
					return new Response('Valor de secret requerido', { status: 400 });
				}

				if (resolveSecretKey(secretName)) {
					return new Response('El secret ya existe en variables del Worker', { status: 409 });
				}

				const existingKv = await readKvSecret(secretName);
				if (existingKv !== null) {
					return new Response('El secret ya existe', { status: 409 });
				}

				await secrets.SECRETS_KV.put(secretName, secretValue);
				return new Response(`Secret "${secretName}" agregado correctamente`, { status: 201 });
			} catch {
				return new Response('Error procesando request', { status: 400 });
			}
		}

		if (url.pathname === '/list-secrets' && request.method === 'POST') {
			try {
				const data = (await request.json()) as { masterKey?: string };
				const authError = validateMasterKey(data.masterKey);
				if (authError) return authError;

				const names = await collectAllSecretNames();
				return Response.json({ secrets: names }, {
					status: 200,
					headers: { 'Cache-Control': 'no-store' },
				});
			} catch {
				return new Response('Error procesando request', { status: 400 });
			}
		}

		if (url.pathname === '/get-secret' && request.method === 'POST') {
			try {
				const data = (await request.json()) as { masterKey?: string; secretName?: string };
				const { masterKey, secretName: rawSecretName } = data;

				const authError = validateMasterKey(masterKey);
				if (authError) return authError;

				const secretName = normalizeSecretName(rawSecretName ?? '');
				if (!secretName) {
					return new Response('Nombre de secret requerido', { status: 400 });
				}

				const matchedSecretName = resolveSecretKey(secretName);
				if (matchedSecretName) {
					const value = readString(matchedSecretName);
					if (value) {
						return new Response(value, { status: 200 });
					}
				}

				const kvValue = await readKvSecret(secretName);
				if (kvValue !== null) {
					return new Response(kvValue, { status: 200 });
				}

				return new Response('Secret no encontrado', { status: 404 });
			} catch {
				return new Response('Error procesando request', { status: 400 });
			}
		}

		if (url.pathname === '/' || url.pathname === '/index.html') {
			return await fetch(new Request(`${url.origin}/index.html`, request));
		}

		return new Response('Not Found', { status: 404 });
	},
} satisfies ExportedHandler<Env>;
