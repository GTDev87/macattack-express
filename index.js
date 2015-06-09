var macattack = require("../macattack");

function getTokenFromReq(req, headerKey) {
  if (req.headers && req.headers.authorization) {
    var parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0] === headerKey) {
      return parts[1];
    }
  }
  throw new Error("macaroon not found");
}

module.exports = function (optionsObj) {
  var options = optionsObj || {};

  console.log("options set for macattack express");
  return function (req, res, next){

    console.log("running pre request");

    var headerKey = optionsObj.headerKey || 'Bearer';

    var serializedMac;
    var route = req.path;
    var databaseSecret = optionsObj.secret || "secret";
    var requestData = req.body;
    var action = req.method;

    try {
      serializedMac = getTokenFromReq(req, headerKey);
    }catch (e) {
      return next(e);
    }

    if(!macattack.validateMac(serializedMac, databaseSecret, route, action, requestData)) { 
      return next(new Error("Macaroon is not valid ")); 
    }
    return next();
  }
};