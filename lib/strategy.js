/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , lookup = require('./utils').lookup;


/**
 * `Strategy` constructor.
 *
 * The local authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `passwordField`  field name where the password is found, defaults to _password_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new JbLocalStrategy(
 *       function(username, password, done) {
 *         User.findOne({ username: username, password: password }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('JbLocalStrategy requires a verify callback'); }

  this._emailField = options.emailField || 'email';
  this._passwordField = options.passwordField || 'password';
  this._isGuestField = options.isGuestField || 'isGuest';
  this._isOcField = options.isOcField || 'isOc';

  passport.Strategy.call(this);
  this.name = 'jblocal';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {

  options = options || {};
  var email = lookup(req.body, this._emailField) || '';
  var password = lookup(req.body, this._passwordField) || '';
  var isGuest = lookup(req.body, this._isGuestField) || 0;
  var isOc = lookup(req.body, this._isOcField) || 0;

  if(parseInt(isGuest, 10) === 0) {
      if (!email || !password) {
        return this.fail({ message: options.badRequestMessage || 'Missing credentials' }, 400);
      }
  }

  isGuest = (parseInt(isGuest, 10) === 0) ? false : true;
  isOc = (parseInt(isOc, 10) === 0) ? false : true;

  var formData = {
    "Email": email,
    "IsGuest": isGuest,
    "IsOC": isOc,
    "Password": password
  };


  var self = this;

  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }

  try {
    if (self._passReqToCallback) {
      this._verify(req, formData, verified);
    } else {
      this._verify(formData, verified);
    }
  } catch (ex) {
    return self.error(ex);
  }
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
