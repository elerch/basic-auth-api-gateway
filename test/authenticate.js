'use strict';
var authenticate = require('../authenticate.js').authenticate;
var expect = require('chai').expect;
var currentState = {};
function getContext() {
  return {
    currentState : {},
    succeed : function(policy) {
      currentState = {
        result : 'success',
        policy : policy
      };
    },
    fail : function(msg) {
      currentState = {
        result : 'fail',
        message : msg
      };
    }
  };
}

describe('auth(req)', function () {
  it ('should succeed on valid credentials', function() {
    var context = getContext();
    authenticate(
      {authorizationToken: "basic Zm9vOmJhcg=="}, // foo, bar
      context, undefined, {user: 'foo', pass: 'bar'});
    expect(currentState.result).to.equal('success');
    // no other assertions at this time - policy later
    //console.log(currentState.policy);
  });

  it ('should fail on invalid credentials', function() {
    var context = getContext();
    authenticate(
      {authorizationToken: "basic Zm9vOmJhcg=="}, // foo, bar
      context, undefined, {user: 'foo', pass: 'qux'});
    expect(currentState.result).to.equal('fail');
    // no other assertions at this time - policy later
    //console.log(currentState.policy);
  });

  it ('should create a good policy on success', function() {
    var context = getContext();
    var expectedStatement = [ { Action: 'execute-api:Invoke',
    Effect: 'Allow',
    Resource: 'arn:ec2::*' } ];

    authenticate(
      {authorizationToken: "basic Zm9vOmJhcg==", // foo, bar
       methodArn: "arn:ec2::*"}, // will be resource in policy
      context, undefined,{user: 'foo', pass: 'bar'});

    expect(currentState.policy.principalId).to.equal('foo');
    expect(currentState.policy.policyDocument.Statement.toString())
      .to.equal(expectedStatement.toString());
  });

  it ('should work with environment variables', () => {
    let context = getContext();
    process.env.AUTH_USER = 'foo';
    process.env.AUTH_PASS = 'bar';
    authenticate(
      {authorizationToken: 'basic Zm9vOmJhcg=='}, context);
    expect(currentState.result).to.equal('success');

    process.env.AUTH_PASS = 'nobueno';
    authenticate(
      {authorizationToken: 'basic Zm9vOmJhcg=='}, context);
    expect(currentState.result).to.equal('fail');
  });

  it ('should work without "basic" preamble', () => {
    let context = getContext();
    process.env.AUTH_USER = 'foo';
    process.env.AUTH_PASS = 'bar';
    authenticate({authorizationToken: 'Zm9vOmJhcg=='}, context);
    expect(currentState.result).to.equal('success');
  });
});
