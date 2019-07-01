# Passport-DLive

[Passport](http://passportjs.org/) strategy for authenticating with
[DLive](https://dlive.tv) using the OAuth 2.0 API.

This module lets you authenticate using DLive in your Node.js applications.
By plugging into Passport, DLive authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    npm install passport-dlive

## Usage

### Create an Application

Before using `passport-dlive`, you must register an application with
DLive.  If you have not already done so, a new application can be created at
[DLive Docs](https://docs.dlive.tv/api/authentication-oauth2/oauth-2.0).  
Your application will be issued an app ID and app secret, which need to be
provided to the strategy. You will also need to configure a redirect URI which
matches the route in your application.

### Configure Strategy

The DLive authentication strategy authenticates users using a DLive
account and OAuth 2.0 tokens.  The app ID and secret obtained when creating an
application are supplied as options when creating the strategy.  The strategy
also requires a `verify` callback, which receives the access token and optional
refresh token, as well as `profile` which contains the authenticated user's
DLive profile.  The `verify` callback must call `cb` providing a user to
complete authentication.
