var macattack = require("macattack");

function getTokenFromReq(req, headerKey) {
  if (req.headers && req.headers.authorization) {
    var parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0] === headerKey) { return parts[1]; }
  }
  throw new Error("macaroon not found");
}

module.exports = function (optionsObj) {
  var options = optionsObj || {};
  return function (req, res, next){
    var serializedMac;

    try { serializedMac = getTokenFromReq(req, optionsObj.headerKey || 'Bearer'); }
    catch (e) { return next(e); }

    //separate out 3rd party caveat portion

    if(!macattack.validateMac(serializedMac, optionsObj.secret || "secret", req.body)) { 
      // validateMac(serializedMac, databaseSecret, requestData);

      return next(new Error("Macaroon is not valid ")); 
    }

    return next();
  }
};