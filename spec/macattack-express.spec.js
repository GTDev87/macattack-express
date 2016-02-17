'use strict';

var MacAttackExpress = require("../index.js");
var pem = require("pem");
var NodeRSA = require("node-rsa");
var macaroons = require("node-macaroons");

(function () {
  describe('createMac', function () {

    var res = {};

    function getBlankRequest(returnCert) {
      return {
        headers: {
          authorization: ""}, 
          connection : {
            getPeerCertificate: function () {return {raw: returnCert}}}};

    }

    describe("running middleware", function () {
      var middlewareFn = null;
      var privKey = null;
      var pubKey = null;
      var certificate = null;

      beforeEach(function(done) {
        pem.createCertificate({days:1, selfSigned:true}, function(err, keys){
          privKey = keys.clientKey;
          certificate = keys.certificate;
          pubKey = keys.serviceKey;

          MacAttackExpress({secret: "secret", hostPort: 443, hostIp: "127.0.0.1", cert: certificate}, function (err, middlewareFnObj) {
            if(err) { return fail(err); }
            middlewareFn = middlewareFnObj;
            done();
          });
        });
      });

      describe('running with no macaroon', function (){
        var err = null;

        beforeEach(function(done) {
          var req = getBlankRequest(certificate);

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
          var req = getBlankRequest(certificate);

          //macaroon is an object
          var serializedMacaroon = macaroons.serialize(middlewareFn.client_macaroon);
          req.headers.authorization = "Bearer " + serializedMacaroon;

          middlewareFn(req, res, function (errObj) {
            err = errObj;
            done();
          });
        });

        it("should display 'Macaroon is not valid'", function (){
          expect(err.message).toEqual("Macaroon is not valid ");
        });
      });

      describe('running with macaroon/discharge pair', function (){
        var err = null;

        beforeEach(function(done) {
          var client_macaroon = middlewareFn.client_macaroon;
          var serializedMacaroon = macaroons.serialize(middlewareFn.client_macaroon);
          var req = getBlankRequest(certificate);

          function getDischarge(loc, thirdPartyLoc, cond, onOK, onErr) {
            var key = new NodeRSA();
            key.importKey(privKey);
            
            var dischargeSerialized = cond.split(" = ")[1];
            var decryptedIdentifier = key.decrypt(dischargeSerialized).toString('utf8');
            var splitIdentifier = decryptedIdentifier.split("\n").filter(function (n) { return n;});
            var splitCaveatKey = splitIdentifier[0].split(" ");
            var caveatKey = splitCaveatKey[splitCaveatKey.length - 1];
            var dischargeMac = macaroons.newMacaroon(caveatKey, cond, thirdPartyLoc);
            onOK(dischargeMac);
          }

          macaroons.discharge(client_macaroon, getDischarge, function(discharges) {
            var serializedDischarge = macaroons.serialize(discharges[1]);
            req.headers.authorization = "Bearer " + serializedMacaroon + "," + serializedDischarge;

            middlewareFn(req, res, function (errObj) {
              err = errObj;
              done();
            });
          }, function(err) {
            throw new Error('error callback called unexpectedly: ' + err);
          });
        });

        it("should display 'Macaroon is not valid'", function (){
          expect(err).toEqual(undefined);
        });
      });
    });

    //NOTE FOR WORKING CASE NEED DISCHAREGE MAC... will write later
  });
})();