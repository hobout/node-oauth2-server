
var error = require('./error')
  , runner = require('./runner')
  , token = require('./token');

module.exports = AuthImplicitGrant;

var fns = [
  checkParams,
  checkClient,
  checkUserApproved,
  generateAccessToken,
  saveAccessToken,
  redirect
];

function AuthImplicitGrant(config, req, res, next, check) {
  this.config = config;
  this.model = config.model;
  this.req = req;
  this.res = res;
  this.check = check;

  var self = this;
  runner(fns, this, function (err) {
    if (err && res.oauthRedirect) {
      // Custom redirect error handler
      res.redirect(self.client.redirectUri + '?error=' + err.error +
        '&error_description=' + err.error_description + '&code=' + err.code);

      return self.config.continueAfterResponse ? next() : null;
    }

    next(err);
  });
}

function checkParams(done) {
  var body = this.req.body;
  var query = this.req.query;
  if (!body && !query) return done(error('invalid_request'));

  // Response type
  this.responseType = body.response_type || query.response_type;
  if (this.responseType !== 'token') {
    return done(error('invalid_request',
      'Invalid response_type parameter (must be "token")'));
  }

  // Client
  this.clientId = body.client_id || query.client_id;
  if (!this.clientId) {
    return done(error('invalid_request',
      'Invalid or missing client_id parameter'));
  }

  // Redirect URI
  this.redirectUri = body.redirect_uri || query.redirect_uri;
  if (!this.redirectUri) {
    return done(error('invalid_request',
      'Invalid or missing redirect_uri parameter'));
  }

  done();
}

function checkClient(done) {
  var self = this;
  this.model.getClient(this.clientId, null, function (err, client) {
    if (err) return done(error('server_error', false, err));

    if (!client) {
      return done(error('invalid_client', 'Invalid client credentials'));
    } else if (Array.isArray(client.redirectUri)) {
      if (client.redirectUri.indexOf(self.redirectUri) === -1) {
        return done(error('invalid_request', 'redirect_uri does not match'));
      }
      client.redirectUri = self.redirectUri;
    } else if (client.redirectUri !== self.redirectUri) {
      return done(error('invalid_request', 'redirect_uri does not match'));
    }

    // The request contains valid params so any errors after this point
    // are redirected to the redirect_uri
    self.res.oauthRedirect = true;
    self.client = client;

    done();
  });
}

function checkUserApproved(done) {
  var self = this;
  this.check(this.req, function (err, allowed, user) {
    if (err) return done(error('server_error', false, err));

    if (!allowed) {
      return done(error('access_denied',
        'The user denied access to your application'));
    }

    self.user = user;
    done();
  });
}

function generateAccessToken(done) {
  var self = this;
  token(this, 'access_token', function (err, token) {
    self.accessToken = token;
    done(err);
  });
}

function saveAccessToken(done) {
  var expires = new Date();
  expires.setSeconds(expires.getSeconds() + this.config.accessTokenLifetime);

  this.model.saveAccessToken(this.accessToken, this.client.clientId, expires, this.user, function (err) {
    if (err) return done(error('server_error', false, err));
    done();
  });
}

function redirect (done) {
  this.res.redirect(this.client.redirectUri + '?access_token=' + this.accessToken + (this.req.query.state ? '&state=' + this.req.query.state : ''));

  if (this.config.continueAfterResponse)
    return done();
}

