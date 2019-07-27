'use strict';

function AuthorizationError(message, code, uri, status) {
	if (!status) {
		// eslint-disable-next-line default-case
		switch (code) {
		case 'access_denied': status = 403;
			break;
		case 'server_error': status = 502;
			break;
		case 'temporarily_unavailable': status = 503;
			break;
		}
	}

	Error.call(this);
	Error.captureStackTrace(this, this.constructor);
	this.name = this.constructor.name;
	this.message = message;
	this.code = code || 'server_error';
	this.uri = uri;
	this.status = status || 500;
}

module.exports = AuthorizationError;

