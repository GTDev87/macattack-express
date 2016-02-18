var macattack = require("macattack"),
  macaroons = require("node-macaroons"),
  cert_encoder = require("cert_encoder")
  pem = require("pem"),
  crypto = require('crypto'),
  publicKeyMacaroons = require('public-key-macaroons'),
  https = require("https");

function getTokenFromReq(req, headerKey) {
  if (req.headers && req.headers.authorization) {
    var parts = req.headers.authorization.split(' ');
    if (parts.length > 1 && parts[0] === headerKey) { return parts.slice(1).join(" "); }
  }
  throw new Error("macaroon not found");
}

function condenseCertificate(certVar){
  return certVar
    .replace("-----BEGIN CERTIFICATE-----", "")
    .replace("-----END CERTIFICATE-----", "")
    .replace(/\n/g, "");
}

module.exports = function (optionsObj, callback) {
  var options = optionsObj || {};
  options.secret = optionsObj.secret || "secret";
  options.hostPort = optionsObj.hostPort || "443";
  options.hostIp = optionsObj.hostIp || "127.0.0.1";
  options.cert = optionsObj.cert || "cert";

  var serializedMacaroon = macattack.createMac(optionsObj.hostIp, optionsObj.hostPort, optionsObj.secret);

  pem.getPublicKey(optionsObj.cert, function (err, data) {
    if(err) {return callback(err);}

    var caveatKey = crypto.createHash('md5').digest('hex');
    var caveatMacaroon = publicKeyMacaroons.addPublicKey3rdPartyCaveat(serializedMacaroon, "Macattack", caveatKey, "cert = " + condenseCertificate(optionsObj.cert), data.publicKey);
    // Return Express server instance vial callback

    var controllerFn = function (req, res, next){
      var serializedMacs;
      var condensedCert = condenseCertificate(cert_encoder.convert(req.connection.getPeerCertificate().raw));//get rid of newlines and header and footer.

      try { serializedMacs = getTokenFromReq(req, optionsObj.headerKey || 'Bearer'); }
      catch (e) { return next(e); }

      var macs =  serializedMacs
        .split(",")
        .map(function (serialMac) { return serialMac &&  macaroons.deserialize(serialMac); });

      var rootMacVerifier = macaroons.newVerifier(macs[0])
        .secret(optionsObj.secret)
        .discharges(macs.slice(1))
        .addCaveatCheck(function (cav) { return cav === "cert = " + condensedCert; });

      return rootMacVerifier.isVerified() ? next() : next(new Error("Macaroon is not valid "));
    }

    controllerFn.client_macaroon = caveatMacaroon;
    controllerFn.cert = optionsObj.cert;

    return callback(null, controllerFn);
  });
};