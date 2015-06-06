var macattack = require("../macattack");

module.exports = function (optionsObj) {
  var options = optionsObj || {};
  return function (req, res, next){

    if(macattack.validateMac()) { return next(new Error("Macaroon is not valid ")); }

    return next();
  }
};