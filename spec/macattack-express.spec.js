'use strict';

var MacaroonsVerifier = require('macaroons.js').MacaroonsVerifier;
var MacAttackExpress = require("../index.js");

(function () {
  describe('createMac', function () {

    var res = {};
    var next = function (err) {if (err) {console.log("err.message = %j", err.message);} };

    var realSerializedMacaroon = "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMmNpZGVudGlmaWVyIHdlIHVzZWQgb3VyIG90aGVyIHNlY3JldCBrZXkKMDAzMGNpZCB0aGlzIHdhcyBob3cgd2UgcmVtaW5kIGF1dGggb2Yga2V5L3ByZWQKMDA1MXZpZCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD507iE_6VzIomYm5kmCri1MltQwo9pu7qJDiTzbWe-SdASonJMvEXezxP8mXr87hcKMDAxYmNsIGh0dHA6Ly9hdXRoLm15YmFuay8KMDAyZnNpZ25hdHVyZSCVAH8ifGHul9vpp280QK4x0_fJJRO61D-V8_-ip6mLhQo,MDAyMWxvY2F0aW9uIGh0dHA6Ly9hdXRoLm15YmFuay8KMDAzN2lkZW50aWZpZXIgdGhpcyB3YXMgaG93IHdlIHJlbWluZCBhdXRoIG9mIGtleS9wcmVkCjAwMmZzaWduYXR1cmUgvDOvYuPCfD-hWsrDQUl4wMHOEGw2Hp8wKRm7n_gATJgK";

    it('should should run', function (){
      var macattackFn = MacAttackExpress({secret: "secret"});
      var req = {headers: {authorization: ""}};

      macattackFn(req, res, next);
    });

    it('should should run with macaroon', function (){
      var macattackFn = MacAttackExpress({secret: "this is a different super-secret key; never use the same secret twice"});
      var req = {headers: {authorization: "Bearer " + realSerializedMacaroon}};

      macattackFn(req, res, next);
    });
  });
})();