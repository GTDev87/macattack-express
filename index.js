var macattack = require("macattack"),
  macaroons = require("macaroons.js"),
  MacaroonsBuilder = macaroons.MacaroonsBuilder,
  MacaroonsVerifier = macaroons.MacaroonsVerifier,
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

  //This is the initializing portion
  ////////

  var serializedMacaroon = macattack.createMac(optionsObj.hostIp, optionsObj.hostPort, optionsObj.secret);

  pem.getPublicKey(optionsObj.cert, function (err, data) {
    if(err) {return callback(err);}

    var caveatKey = crypto.createHash('md5').digest('hex');
    console.log("cert = %j", optionsObj.cert);

    var caveatMacaroon = publicKeyMacaroons.addPublicKey3rdPartyCaveat(serializedMacaroon, "Macattack", caveatKey, "cert = " + condenseCertificate(optionsObj.cert), data.publicKey);
  
    console.log("client_macaroon=" + JSON.stringify(caveatMacaroon));

    //macattack_express
    pem.createCertificate({days:1, selfSigned:true}, function(err, keys){
      if(err) {return callback(err);}
      var options = {
        key: keys.serviceKey, //do i need to save this off?
        cert: keys.certificate,
       
        // This is necessary only if using the client certificate authentication.
        // Without this some clients don't bother sending certificates at all, some do
        requestCert: true,
       
        // Do we reject anyone who certs who haven't been signed by our recognised certificate authorities
        rejectUnauthorized: false
       
        // This is necessary only if the client uses the self-signed certificate and you care about implicit authorization
        //ca: [ fs.readFileSync('client/client-certificate.pem') ]//TODO how do i get rid of this
      };

      // Return Express server instance vial callback

      return callback(null, function (req, res, next){
        var serializedMacs;
        // TODO LATER 
        var condensedCert = condenseCertificate(cert_encoder.convert(req.connection.getPeerCertificate().raw));//get rid of newlines and header and footer.

        try { serializedMacs = getTokenFromReq(req, optionsObj.headerKey || 'Bearer'); }
        catch (e) { return next(e); }

        var eachMac = serializedMacs.split(",");
        var macs = eachMac.map(function (serialMac) { return serialMac && MacaroonsBuilder.deserialize(serialMac); })

        var rootMac = macs[0];    
        var dischargeMac = macs[1];
        var requestReadyMac = dischargeMac && MacaroonsBuilder.modify(rootMac).prepare_for_request(dischargeMac).getMacaroon();
        var rootMacVerifier = new MacaroonsVerifier(rootMac);
        rootMacVerifier = rootMacVerifier.satisfyExact("cert = " + condensedCert);
        rootMacVerifier = (requestReadyMac ? rootMacVerifier.satisfy3rdParty(requestReadyMac) : rootMacVerifier);

        return rootMacVerifier.isValid(optionsObj.secret) ? next() : next(new Error("Macaroon is not valid "));
      });
      // MUST CALL Afterwards
      // callback(https.createServer(options, app));
    });
  });
};