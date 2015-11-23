/*jslint node: true, vars: true */

var assert = require('assert'),
    util = require('util'),
    ENCODING = 'base64';

//
// Create encoded format that has the following properties
// *has enough information such that the if one has access to encryption key within AWS.KMS one can decrypt the data
// *can be stored or sent over the wire.
// *protects from tampering
//
// The encoded format is as follows - all parts are base64 encoded
//
//        cipherText.iv.cipherKey.keyContext.hmacCode
//
// *cipherText - the encrypted data - encrypted
// *iv - the initalization vector used when created the ciphertext - so two bobs not the same - not encrypted
// *cipherKey - the encrypted version of the key used to encrypt data, for example the edk from AWS generate data key - encrypted
// *keyContext - context used when the data encryption key was generated, required if want to get clear text key.
//   **The key context is also used for Audit in AWS as written to cloud trail when key is accessed. The format can be anything an example is
//     type: serviceName:resource  (ln-connector:poc1.webshield.io.key.pem)
//     id: none
// *hmacCode -  hmacCode across the cipherText, iv, edk, edkContext. Used to make sure format not tampered with and protects against oracle padding attacks.
//

//
// Create the 'encoded' format from passed in params.
//  - cipherText - A Buffer - For convenience will convert non Buffer to a Buffer
//  - iv - a Buffer
/// - edk - a Buffer
//  - edkContext - is a JS object
//  - hmacCode - a Buffer
function encode(params) {
  'use strict';
  var cipherText;
  assert(params.cipherText, util.format('no params.cipherText:%j', params)); // can be a string or a Buffer
  assert(params.iv, util.format('no params.iv:%j', params));
  assert(params.cipherKey, util.format('no params.cipherKey:%j', params));
  assert(params.keyContext, util.format('no params.keyContext:%j', params)); // is expected to be a JS object
  assert(params.hmacCode, util.format('no params.hmacCode:%j', params)); // expect to be in base64 code already

  if (!(params.cipherText instanceof Buffer)) {
    cipherText = new Buffer(params.cipherText);
  } else {
    cipherText = params.cipherText;
  }

  return cipherText.toString(ENCODING) + '.' + params.iv.toString(ENCODING) + '.' +
        params.cipherKey.toString(ENCODING) + '.' + new Buffer(JSON.stringify(params.keyContext)).toString(ENCODING) + '.' +
        params.hmacCode;  //hmac.digest(ENCODING);
}

//
// Converts from encoded format into a object - all data is returned in a Buffer and caller interprets
// *smft - the item to unpack
//
function decode(sfmt) {
  'use strict';
  var unpack = {}, t;
  t = sfmt.split('.');

  unpack.cipherText = new Buffer(t[0], ENCODING);
  unpack.iv = new Buffer(t[1], ENCODING);

  unpack.cipherKey =  new Buffer(t[2], ENCODING);
  unpack.keyContext =  JSON.parse(new Buffer(t[3], ENCODING).toString()); // fixme add try.catch

  unpack.hmacCode = t[4];

  return unpack;
}

module.exports = {
  decode: decode,
  encode: encode
};
