'use strict';

var MacaroonsVerifier = require('macaroons.js').MacaroonsVerifier;
var MacAttackExpress = require("../index.js");

(function () {
  describe('createMac', function () {

    var res = {};

    var realSerializedMacaroon = "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMmNpZGVudGlmaWVyIHdlIHVzZWQgb3VyIG90aGVyIHNlY3JldCBrZXkKMDAzMGNpZCB0aGlzIHdhcyBob3cgd2UgcmVtaW5kIGF1dGggb2Yga2V5L3ByZWQKMDA1MXZpZCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD507iE_6VzIomYm5kmCri1MltQwo9pu7qJDiTzbWe-SdASonJMvEXezxP8mXr87hcKMDAxYmNsIGh0dHA6Ly9hdXRoLm15YmFuay8KMDAyZnNpZ25hdHVyZSCVAH8ifGHul9vpp280QK4x0_fJJRO61D-V8_-ip6mLhQo,MDAyMWxvY2F0aW9uIGh0dHA6Ly9hdXRoLm15YmFuay8KMDAzN2lkZW50aWZpZXIgdGhpcyB3YXMgaG93IHdlIHJlbWluZCBhdXRoIG9mIGtleS9wcmVkCjAwMmZzaWduYXR1cmUgvDOvYuPCfD-hWsrDQUl4wMHOEGw2Hp8wKRm7n_gATJgK";

    var realCertificate = 
      "-----BEGIN CERTIFICATE-----\n" + 
      "MIICpDCCAYwCCQCwh3WFyZu5YDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwls\n" + 
      "b2NhbGhvc3QwHhcNMTUxMTA5MTgzOTUxWhcNMTUxMTEwMTgzOTUxWjAUMRIwEAYD\n" + 
      "VQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc\n" +
      "CaQcJgQix0v49zjo3qBheRRplJG0QgzmYaYAJPA+VVJSw3nzfgKAlI8YlTDpVAOu\n" +
      "kOaGRLwr2yuc2yguYO8efaXVxgcGPuOQ0ueFcMxhcS8rXVLsfLQdBdN7XQ4KGg2A\n" +
      "yOwnwFcOF/L1FKY2arB7AcCVdCBm5KvOQa4VNcANDOF9c8Z/tJY5Sri1HpELL2LA\n" +
      "sHlfrdL1IlNt6TV78UrYNET6VKoxTcjQPvSXo/NUqnByOKELCMQjM07O6fVfhFBT\n" +
      "DFv3iiPHbT2GhIEGGRwv3wiQan5MlG1VixUshxaIxwFm6xakyW39S7grFv7N7yBy\n" +
      "aOaKbl4+kAW1C7YhMiINAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADU2UIX95Nbk\n" +
      "WrCJjTnjUBOlMPCUYIxKZk6ocJFT6ad3Um4eBcejOg7aj+m3h62dNi6w6LxCFaXN\n" +
      "BGLmgvLV1CQclBjK6vWrBfjoq/qFKlcRf+GGyREd/EzoyXq33ssBQAYGRQBlv/4R\n" +
      "+BGkjRsZ+5iJAS6RnGrZRHXPORwqioHjfaZwMJc5xjvR9NhQlWhcSMg2naNQhgNA\n" + 
      "rmqanXRKdCIeuZNxokCTi+paNvSFdqKUOPqipX1C9CpthzIZg9JOm1KWFEOgtTh3\n" + 
      "HuLknwXj/UlJnT1XpewFUI/34jfaX1+x11dxm9Xf+cJ03mtNLbGTTVHYp//8OL7/\n" + 
      "2l+hP7wECNo=\n" +
      "-----END CERTIFICATE-----";

    function getBlankRequest(returnCert) {
      return {
        headers: {
          authorization: ""}, 
          connection : {
            getPeerCertificate: function () {return {raw: returnCert}}}};

    }

    describe("running middleware", function () {
      var middlewareFn = null;

      beforeEach(function(done) {
        MacAttackExpress({secret: "secret", hostPort: 443, hostIp: "127.0.0.1", cert: realCertificate}, function (err, middlewareFnObj) {
          if(err) { return fail(err); }
          middlewareFn = middlewareFnObj;
          done();
        });
      });

      describe('running with no macaroon', function (){
        var err = null;

        beforeEach(function(done) {
          var req = getBlankRequest(realCertificate);
          middlewareFn(req, res, function (errObj) {
            err = errObj;
            done();
          });
        });

        it("should display 'macaroon not found'", function (){
          expect(err.message).toEqual("macaroon not found");
        });
      });

      describe('running with invalid macaroon', function (){
        var err = null;

        beforeEach(function(done) {
          var req = getBlankRequest(realCertificate);
          req.headers.authorization = "Bearer " + realSerializedMacaroon;
          middlewareFn(req, res, function (errObj) {
            err = errObj;
            done();
          });
        });

        it("should display 'Macaroon is not valid'", function (){
          expect(err.message).toEqual("Macaroon is not valid ");
        });
      });
    });

    //NOTE FOR WORKING CASE NEED DISCHAREGE MAC... will write later
  });
})();