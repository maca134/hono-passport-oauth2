import { randomBytes } from "crypto";
import type { Context } from "hono";
import { type HonoPassportStrategy, PassportError } from "@maca134/hono-passport";
import type { HonoSessionEnv } from "@maca134/hono-session";


type OAuth2SessionData = {
	__oauth2state__?: string;
};

export type OAuth2StrategyStateStore = {
	generate: (ctx: Context<HonoSessionEnv<OAuth2SessionData>>) => string;
	verify: (ctx: Context<HonoSessionEnv<OAuth2SessionData>>, state: string) => boolean;
};

export type OAuth2StrategyOptions = {
	authorizeURL: string;
	tokenURL: string;
	clientID: string;
	clientSecret: string;
	returnURL: string;
	scope?: string;
	state?: boolean;
	store?: OAuth2StrategyStateStore;
};

export type OAuth2Token = {
	access_token: string;
	token_type: string;
	expires_in: number;
	refresh_token?: string;
	scope: string;
};

const store: OAuth2StrategyStateStore = {
	generate: ctx => {
		const state = randomBytes(8).toString('hex');
		ctx.var.session.data.__oauth2state__ = state;
		return state;
	},
	verify: (ctx, state) => {
		const valid = ctx.var.session.data.__oauth2state__ === state;
		ctx.var.session.data.__oauth2state__ = undefined;
		return valid;
	},
};

export function oauth2Strategy<TUser>(
	options: OAuth2StrategyOptions,
	validate: (
		ctx: Context,
		token: OAuth2Token,
	) => Promise<TUser | undefined>,
): HonoPassportStrategy<TUser> {
	if (options.state && !options.store) {
		options.store = store;
	}
	return {
		name: 'oauth2',
		authenticate: async (ctx, complete) => {
			if (!ctx.req.query('code')) {
				const params = new URLSearchParams();
				params.set('client_id', options.clientID);
				params.set('redirect_uri', options.returnURL);
				params.set('response_type', 'code');
				if (options.state) {
					params.set('state', options.store!.generate(ctx as Context<HonoSessionEnv<OAuth2SessionData>>));
				}
				if (options.scope) {
					params.set('scope', options.scope);
				}
				return ctx.redirect(`${options.authorizeURL}?${params.toString()}`);
			}

			if (options.state && (!ctx.req.query('state') || !options.store!.verify(ctx as Context<HonoSessionEnv<OAuth2SessionData>>, ctx.req.query('state')!))) {
				throw new PassportError(`Invalid state parameter.`);
			}

			const code = ctx.req.query('code')!;

			const tokenParams = new URLSearchParams();
			tokenParams.set('redirect_uri', options.returnURL);
			if (options.scope) {
				tokenParams.set('scope', options.scope);
			}
			tokenParams.set('grant_type', 'authorization_code');
			tokenParams.set('code', code);

			const response = await fetch(options.tokenURL, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
					Authorization: `Basic ${Buffer.from(`${options.clientID}:${options.clientSecret}`).toString('base64')}`,
				},
				body: tokenParams,
			});

			if (!response.ok) {
				throw new PassportError(`Failed to get token: ${response.statusText}`);
			}

			const token = await response.json() as OAuth2Token;

			const user = await validate(ctx, token);
			if (user) {
				await complete(user);
			}
		},
	};
}

