/**
 * RegExp for basic auth credentials
 *
 * credentials = auth-scheme 1*SP token68
 * auth-scheme = "Basic" ; case insensitive
 * token68     = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
 * @private
 */

var credentialsRegExp = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9\-\._~\+\/]+=*) *$/;

/**
 * RegExp for basic auth user/pass
 *
 * user-pass   = userid ":" password
 * userid      = *<TEXT excluding ":">
 * password    = *TEXT
 * @private
 */

var userPassRegExp = /^([^:]*):(.*)$/;

function userFromBasicAuthString(header) {
  // parse header
  var match = credentialsRegExp.exec(header || '');

  if (!match) {
    return null;
  }

  // decode user pass
  var userPass = userPassRegExp.exec(decodeBase64(match[1]));

  if (!userPass) {
    return null;
  }

  // return credentials object
  return new Credentials(userPass[1], userPass[2]);
}

/**
 * Decode base64 string.
 * @private
 */

function decodeBase64(str) {
  return new Buffer(str, 'base64').toString();
}

/**
 * Object to represent user credentials.
 * @private
 */

function Credentials(name, pass) {
  this.name = name;
  this.pass = pass;
}

exports.authenticate = function(event, context, config) {
  var token = event.authorizationToken;
  // Call oauth provider, crack jwt token, etc.
  // In this example, the token is treated as the status for simplicity.
  var user = userFromBasicAuthString(token);
  var configFn = typeof config === 'function' ?
                  config :
                  function() { return config; };
  var finalConfig = configFn() || serverConfig;

  if (!user || !user.name || !user.pass) {
    context.fail("error");
    return;
  }

  if (user.name === finalConfig.user && user.pass === finalConfig.pass) {
    context.succeed(generatePolicy(user.name, 'Allow', event.methodArn));
    return;
  } else {
    context.fail("Unauthorized");
    return;
  }
  // should not reach this point
  // context.fail("error");
};

function generatePolicy(principalId, effect, resource) {
  var authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    var policyDocument = {};
    policyDocument.Version = '2012-10-17'; // default version
    policyDocument.Statement = [];
    var statementOne = {};
    statementOne.Action = 'execute-api:Invoke'; // default action
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
}
