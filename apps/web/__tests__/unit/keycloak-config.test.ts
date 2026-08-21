import {
	expectedKeycloakCallbackUrl,
	type KeycloakEnv,
	keycloakConfigWarnings,
	missingKeycloakEnv,
	resolveKeycloakConfig,
} from "@cap/database/auth/keycloak";
import { describe, expect, it } from "vitest";

const configured: KeycloakEnv = {
	KEYCLOAK_ISSUER: "https://sso.example.com/realms/cap",
	KEYCLOAK_CLIENT_ID: "cap-web",
	KEYCLOAK_CLIENT_SECRET: "keycloak-secret",
	NEXTAUTH_URL: "https://cap.example.com",
};

describe("resolveKeycloakConfig", () => {
	it("returns null when nothing is configured", () => {
		expect(resolveKeycloakConfig({})).toBeNull();
	});

	it("reads the prefixed credentials", () => {
		expect(resolveKeycloakConfig(configured)).toEqual({
			issuer: "https://sso.example.com/realms/cap",
			clientId: "cap-web",
			clientSecret: "keycloak-secret",
			callbackUrl: null,
		});
	});

	it("falls back to the unprefixed credentials", () => {
		const config = resolveKeycloakConfig({
			KEYCLOAK_ISSUER: "https://sso.example.com/realms/cap",
			CLIENT_ID: "cap-web",
			CLIENT_SECRET: "keycloak-secret",
			CALLBACK_URL: "https://cap.example.com/api/auth/callback/keycloak",
		});

		expect(config).toEqual({
			issuer: "https://sso.example.com/realms/cap",
			clientId: "cap-web",
			clientSecret: "keycloak-secret",
			callbackUrl: "https://cap.example.com/api/auth/callback/keycloak",
		});
	});

	it("prefers the prefixed credentials over the unprefixed ones", () => {
		const config = resolveKeycloakConfig({
			...configured,
			CLIENT_ID: "other-client",
			CLIENT_SECRET: "other-secret",
		});

		expect(config?.clientId).toBe("cap-web");
		expect(config?.clientSecret).toBe("keycloak-secret");
	});

	it("trims whitespace and trailing slashes", () => {
		const config = resolveKeycloakConfig({
			KEYCLOAK_ISSUER: "  https://sso.example.com/realms/cap/  ",
			CLIENT_ID: " cap-web ",
			CLIENT_SECRET: " keycloak-secret ",
			CALLBACK_URL: " https://cap.example.com/api/auth/callback/keycloak/ ",
		});

		expect(config).toEqual({
			issuer: "https://sso.example.com/realms/cap",
			clientId: "cap-web",
			clientSecret: "keycloak-secret",
			callbackUrl: "https://cap.example.com/api/auth/callback/keycloak",
		});
	});

	it("treats blank values as unset", () => {
		expect(
			resolveKeycloakConfig({ ...configured, KEYCLOAK_CLIENT_SECRET: "   " }),
		).toBeNull();
	});
});

describe("missingKeycloakEnv", () => {
	it("lists every credential that is missing", () => {
		expect(missingKeycloakEnv({})).toEqual([
			"KEYCLOAK_ISSUER",
			"KEYCLOAK_CLIENT_ID (or CLIENT_ID)",
			"KEYCLOAK_CLIENT_SECRET (or CLIENT_SECRET)",
		]);
	});

	it("is empty for a complete configuration", () => {
		expect(missingKeycloakEnv(configured)).toEqual([]);
	});
});

describe("expectedKeycloakCallbackUrl", () => {
	it("derives the redirect URI next-auth will send", () => {
		expect(
			expectedKeycloakCallbackUrl({ NEXTAUTH_URL: "https://cap.example.com/" }),
		).toBe("https://cap.example.com/api/auth/callback/keycloak");
	});

	it("returns null without NEXTAUTH_URL", () => {
		expect(expectedKeycloakCallbackUrl({})).toBeNull();
	});
});

describe("keycloakConfigWarnings", () => {
	it("stays quiet when Keycloak is not configured at all", () => {
		expect(
			keycloakConfigWarnings({ NEXTAUTH_URL: "https://cap.example.com" }),
		).toEqual([]);
	});

	it("stays quiet for a matching callback URL", () => {
		expect(
			keycloakConfigWarnings({
				...configured,
				CALLBACK_URL: "https://cap.example.com/api/auth/callback/keycloak",
			}),
		).toEqual([]);
	});

	it("reports a partial configuration", () => {
		const warnings = keycloakConfigWarnings({ CLIENT_ID: "cap-web" });

		expect(warnings).toHaveLength(1);
		expect(warnings[0]).toContain("KEYCLOAK_ISSUER");
		expect(warnings[0]).toContain("KEYCLOAK_CLIENT_SECRET (or CLIENT_SECRET)");
	});

	it("reports a callback URL that Cap will never send", () => {
		const warnings = keycloakConfigWarnings({
			...configured,
			CALLBACK_URL: "https://cap.example.com/api/auth/callback/oidc",
		});

		expect(warnings).toHaveLength(1);
		expect(warnings[0]).toContain(
			"https://cap.example.com/api/auth/callback/keycloak",
		);
	});
});
