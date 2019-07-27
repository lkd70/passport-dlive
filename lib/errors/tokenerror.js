'use strict';

function TokenError(message, code, uri, status) {
	Error.call(this);
	Error.captureStackTrace(this, this.constructor);
	this.name = this.constructor.name;
	this.message = message;
	this.code = code || 'invalid_request';
	this.uri = uri;
	this.status = status || 500;
}

module.exports = TokenError;
