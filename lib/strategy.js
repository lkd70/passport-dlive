'use strict';

const request = require('request');
const passport = require('passport-strategy');
const url = require('url');
const util = require('util');
const { OAuth2 } = require('oauth');
const SessionStateStore = require('./state/session');
const AuthorizationError = require('./errors/authorizationerror');
const TokenError = require('./errors/tokenerror');
const InternalOAuthError = require('./errors/internaloautherror');

class Strategy {
	constructor(options, verify) {
		if (typeof options === 'function') {
			verify = options;
			options = null;
		}
		options = options || {};
		options.authorizationURL = options.authorizationURL || 'https://dlive.tv/o/authorize';
		options.tokenURL = options.tokenURL || 'https://dlive.tv/o/token';
		options.customHeaders = options.customHeaders || { authorization: `Basic ${Buffer.from(`${options.clientID}:${options.clientSecret}`).toString('base64')}` };
		this._callbackURL = options.callbackURL;
		this._scope = options.scope || 'email:read';
		this._scopeSeparator = options.scopeSeparator || ' ';
		this._key = options.sessionKey || 'dlive:' + url.parse(options.authorizationURL).hostname;
		this._apiEndpoint = options.apiEndpoint || 'https://graphigo.prd.dlive.tv';

		if (!verify) throw new TypeError('passport-dlive requires a verify callback');
		if (!options.authorizationURL) throw new TypeError('passport-dlive requires a authorizationURL option');
		if (!options.tokenURL) throw new TypeError('passport-dlive requires a tokenURL option');
		if (!options.clientID) throw new TypeError('passport-dlive requires a clientID option');

		passport.Strategy.call(this);
		this.name = 'dlive';
		this._verify = verify;

		this._oauth2 = new OAuth2(
			options.clientID, options.clientSecret,
			'', options.authorizationURL, options.tokenURL, options.customHeaders
		);

		if (options.store) {
			this._stateStore = options.store;
		} else {
			this._stateStore = new SessionStateStore({ key: this._key });
		}
		this._trustProxy = options.proxy;
		this._passReqToCallback = options.passReqToCallback;
		this._skipUserProfile = typeof options.skipUserProfile === 'undefined' ? false : options.skipUserProfile;
	}

	userProfile(authorization, callback) {
		this.authorization = authorization;
		this.callback = callback;
		request.post(this._apiEndpoint, {
			headers: { authorization },
			json: { query: `query{me{username displayname avatar about createdAt partnerStatus private{email}}}` }
		}, (err, r, body) => {
			if (err) {
				return callback(new InternalOAuthError('', err));
			}
			try {
				callback(null, body);
			} catch (e) {
				callback(e);
			}
		});
	}

	authenticate(req, options) {
		options = options || {};
		const self = this;

		if (req.query && req.query.error) {
			if (req.query.error === 'access_denied') {
				return this.fail({ message: req.query.error_description });
			}
			return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
		}

		const callbackURL = options.callbackURL || this._callbackURL;

		const meta = {
			authorizationURL: this._oauth2._authorizeUrl,
			clientID: this._oauth2._clientId,
			tokenURL: this._oauth2._accessTokenUrl,
		};

		function loaded(err, ok, state) {
			if (err) return self.error(err);
			if (!ok) return self.fail(state, 403);
			const { code } = req.query;

			const params = self.tokenParams(options);
			params.grant_type = 'authorization_code';
			params.redirect_uri = callbackURL;

			self._oauth2.getOAuthAccessToken(
				code, params,
				(err, accessToken, refreshToken, params) => {
					if (err) return self.error(self._createOAuthError('Failed to obtain access token', err));

					self._loadUserProfile(accessToken, (err, profile) => {
						if (err) return self.error(err);

						function verified(err, user, info) {
							if (err) return self.error(err);
							if (!user) return self.fail(info);

							info = info || {};
							if (state) info.state = state;
							self.success(user, info);
						}

						try {
							if (self._passReqToCallback) {
								const arity = self._verify.length;
								if (arity === 6) {
									self._verify(req, accessToken, refreshToken, params, profile, verified);
								} else {
									self._verify(req, accessToken, refreshToken, profile, verified);
								}
							} else {
								const arity = self._verify.length;
								if (arity === 5) {
									self._verify(accessToken, refreshToken, params, profile, verified);
								} else {
									self._verify(accessToken, refreshToken, profile, verified);
								}
							}
						} catch (ex) {
							return self.error(ex);
						}
					});
				}
			);
		}

		if (req.query && req.query.code) {
			const { state } = req.query;
			try {
				const arity = this._stateStore.verify.length;
				if (arity === 4) {
					this._stateStore.verify(req, state, meta, loaded);
				} else {
					this._stateStore.verify(req, state, loaded);
				}
			} catch (ex) {
				return this.error(ex);
			}
		} else {
			const params = this.authorizationParams(options);
			params.response_type = 'code';
			params.redirect_uri = callbackURL;
			let scope = options.scope || this._scope;
			if (scope) {
				if (Array.isArray(scope)) scope = scope.join(this._scopeSeparator);
				params.scope = scope;
			}
			let verifier;

			const { state } = options;
			if (state) {
				params.state = state;
				const parsed = url.parse(this._oauth2._authorizeUrl, true);
				parsed.query = { ...parsed.query, ...params };
				parsed.query.client_id = this._oauth2._clientId;
				delete parsed.search;
				const location = url.format(parsed);
				this.redirect(location);
			} else {
				function stored(err, _state) {
					if (err) return self.error(err);

					if (_state) params.state = _state;
					const parsed = url.parse(self._oauth2._authorizeUrl, true);
					parsed.query = { ...parsed.query, ...params };
					parsed.query.client_id = self._oauth2._clientId;
					delete parsed.search;
					const location = url.format(parsed);
					self.redirect(location);
				}

				try {
					const arity = this._stateStore.store.length;
					if (arity === 5) {
						this._stateStore.store(req, verifier, null, meta, stored);
					} else if (arity === 3) {
						this._stateStore.store(req, meta, stored);
					} else {
						this._stateStore.store(req, stored);
					}
				} catch (ex) {
					return this.error(ex);
				}
			}
		}
	}

	authorizationParams(options) {
		this.options = options;
		return {};
	}

	tokenParams(options) {
		this.options = options;
		return {};
	}

	parseErrorResponse(body) {
		this.body = body;
		const json = JSON.parse(this.body);
		if (json.error) {
			return new TokenError(json.error_description, json.error, json.error_uri);
		}
		return null;
	}

	_loadUserProfile(accessToken, done) {
		const self = this;

		function loadIt() {
			return self.userProfile(accessToken, done);
		}
		function skipIt() {
			return done(null);
		}

		if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
			this._skipUserProfile(accessToken, (err, skip) => {
				if (err) return done(err);
				if (!skip) return loadIt();
				return skipIt();
			});
		} else {
			const skip = typeof this._skipUserProfile == 'function' ? this._skipUserProfile() : this._skipUserProfile;
			if (!skip) return loadIt();
			return skipIt();
		}
	}

	_createOAuthError(message, err) {
		let new_err;
		if (err.statusCode && err.data) {
			try {
				new_err = this.parseErrorResponse(err.data, err.statusCode);
			} catch (error) {
				new_err = new InternalOAuthError(message, err);
			}
		}
		return new_err;
	}
}

util.inherits(Strategy, passport.Strategy);


module.exports = Strategy;
