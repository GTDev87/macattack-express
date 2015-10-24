var macattack = require("macattack"),
  macaroons = require("macaroons.js"),
  MacaroonsBuilder = macaroons.MacaroonsBuilder,
  MacaroonsVerifier = macaroons.MacaroonsVerifier,
  cert_encoder = require("cert_encoder");

function getTokenFromReq(req, headerKey) {
  if (req.headers && req.headers.authorization) {
    var parts = req.headers.authorization.split(' ');
    if (parts.length > 1 && parts[0] === headerKey) { return parts.slice(1).join(" "); }
  }
  throw new Error("macaroon not found");
}

module.exports = function (optionsObj) {
  var options = optionsObj || {};
  return function (req, res, next){
    var serializedMacs;
    // TODO LATER 
    var condensedCert = cert_encoder.convert(req.connection.getPeerCertificate().raw)
      .replace(/\n/g, "")
      .replace("-----BEGIN CERTIFICATE-----", "")
      .replace("-----END CERTIFICATE-----", "");//get rid of newlines and header and footer.

    try { serializedMacs = getTokenFromReq(req, optionsObj.headerKey || 'Bearer'); }
    catch (e) { return next(e); }

    var eachMac = serializedMacs.split(",");
    var macs = eachMac.map(function (serialMac) { return serialMac && MacaroonsBuilder.deserialize(serialMac); })

    var rootMac = macs[0];    var dischargeMac = macs[1];
    var requestReadyMac = dischargeMac && MacaroonsBuilder.modify(rootMac).prepare_for_request(dischargeMac).getMacaroon();
    var rootMacVerifier = new MacaroonsVerifier(rootMac);
    rootMacVerifier = rootMacVerifier.satisfyExact("cert = " + condensedCert);
    rootMacVerifier = (requestReadyMac ? rootMacVerifier.satisfy3rdParty(requestReadyMac) : rootMacVerifier);

    return rootMacVerifier.isValid(optionsObj.secret || "secret") ? next() : next(new Error("Macaroon is not valid "));
  }
};