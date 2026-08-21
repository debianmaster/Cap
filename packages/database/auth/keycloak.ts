import KeycloakProvider from "next-auth/providers/keycloak";

export const KEYCLOAK_CALLBACK_PATH = "/api/auth/callback/keycloak";

export type KeycloakEnv = {
	KEYCLOAK_ISSUER?: string;
	KEYCLOAK_CLIENT_ID?: string;
	KEYCLOAK_CLIENT_SECRET?: string;
	KEYCLOAK_CALLBACK_URL?: string;
	CLIENT_ID?: string;
	CLIENT_SECRET?: string;
	CALLBACK_URL?: string;
	NEXTAUTH_URL?: string;
};

export type KeycloakConfig = {
	issuer: string;
	clientId: string;
	clientSecret: string;
	callbackUrl: string | null;
};

const value = (raw: string | undefined | null) => {
	const trimmed = raw?.trim();
	return trimmed ? trimmed : undefined;
};

const withoutTrailingSlash = (url: string) => url.replace(/\/+$/, "");

export function resolveKeycloakConfig(env: KeycloakEnv): KeycloakConfig | null {
	const issuer = value(env.KEYCLOAK_ISSUER);
	const clientId = value(env.KEYCLOAK_CLIENT_ID) ?? value(env.CLIENT_ID);
	const clientSecret =
		value(env.KEYCLOAK_CLIENT_SECRET) ?? value(env.CLIENT_SECRET);
	const callbackUrl =
		value(env.KEYCLOAK_CALLBACK_URL) ?? value(env.CALLBACK_URL) ?? null;

	if (!issuer || !clientId || !clientSecret) return null;

	return {
		issuer: withoutTrailingSlash(issuer),
		clientId,
		clientSecret,
		callbackUrl: callbackUrl ? withoutTrailingSlash(callbackUrl) : null,
	};
}

export function missingKeycloakEnv(env: KeycloakEnv): string[] {
	const missing: string[] = [];
	if (!value(env.KEYCLOAK_ISSUER)) missing.push("KEYCLOAK_ISSUER");
	if (!value(env.KEYCLOAK_CLIENT_ID) && !value(env.CLIENT_ID))
		missing.push("KEYCLOAK_CLIENT_ID (or CLIENT_ID)");
	if (!value(env.KEYCLOAK_CLIENT_SECRET) && !value(env.CLIENT_SECRET))
		missing.push("KEYCLOAK_CLIENT_SECRET (or CLIENT_SECRET)");
	return missing;
}

export function expectedKeycloakCallbackUrl(env: KeycloakEnv): string | null {
	const base = value(env.NEXTAUTH_URL);
	return base ? `${withoutTrailingSlash(base)}${KEYCLOAK_CALLBACK_PATH}` : null;
}

export function keycloakConfigWarnings(env: KeycloakEnv): string[] {
	const warnings: string[] = [];
	const partiallyConfigured =
		value(env.KEYCLOAK_ISSUER) ||
		value(env.KEYCLOAK_CLIENT_ID) ||
		value(env.CLIENT_ID) ||
		value(env.KEYCLOAK_CLIENT_SECRET) ||
		value(env.CLIENT_SECRET) ||
		value(env.KEYCLOAK_CALLBACK_URL) ||
		value(env.CALLBACK_URL);

	const config = resolveKeycloakConfig(env);

	if (!config) {
		if (partiallyConfigured)
			warnings.push(
				`Keycloak SSO is partially configured and has been disabled. Missing: ${missingKeycloakEnv(
					env,
				).join(", ")}.`,
			);
		return warnings;
	}

	const expected = expectedKeycloakCallbackUrl(env);
	// next-auth v4 derives the OAuth redirect_uri from NEXTAUTH_URL and offers no
	// per-provider override, so a CALLBACK_URL that disagrees with it only shows
	// up as an opaque invalid_redirect_uri error from Keycloak.
	if (config.callbackUrl && expected && config.callbackUrl !== expected)
		warnings.push(
			`Keycloak CALLBACK_URL (${config.callbackUrl}) does not match the redirect URI Cap sends (${expected}). Register ${expected} in your Keycloak client, or align NEXTAUTH_URL with CALLBACK_URL.`,
		);

	return warnings;
}

const loggedWarnings = new Set<string>();

export function keycloakProvider(env: KeycloakEnv) {
	for (const warning of keycloakConfigWarnings(env)) {
		if (loggedWarnings.has(warning)) continue;
		loggedWarnings.add(warning);
		console.warn(warning);
	}

	const config = resolveKeycloakConfig(env);
	if (!config) return null;

	return KeycloakProvider({
		clientId: config.clientId,
		clientSecret: config.clientSecret,
		issuer: config.issuer,
	});
}
