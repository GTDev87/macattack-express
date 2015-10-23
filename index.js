var macattack = require("macattack");

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
    // var pemCert = cert_encoder.convert(req.connection.getPeerCertificate().raw);//certificate for comprison

    try { serializedMacs = getTokenFromReq(req, optionsObj.headerKey || 'Bearer'); }
    catch (e) { return next(e); }

    var eachMac = serializedMacs.split(",");
    var macs = _.map(eachMac, function (serialMac) { return MacaroonsBuilder.deserialize(serialMac); })

    var rootMac = macs[0];
    var dischargeMac = macs[1];

    var requestReadyMac = dischargeMac && MacaroonsBuilder.modify(rootMac).prepare_for_request(dischargeMac).getMacaroon();
    
    var rootMacVerifier = new MacaroonsVerifier(rootMac);

    rootMacVerifier = (requestReadyMac ? rootMacVerifier.satisfy3rdParty(requestReadyMac) : rootMacVerifier)
    rootMacVerifier = macattack.validateMac(rootMacVerifier, req.body, rootMacVerifier);
    var isValid = rootMacVerifier.isValid(optionsObj.secret || "secret");

    return isValid ? next() : next(new Error("Macaroon is not valid "));
  }
};