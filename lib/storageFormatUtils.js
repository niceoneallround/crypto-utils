/*jslint node: true, vars: true */

var assert = require('assert'),
    util = require('util'),
    ENCODING = 'base64';

//
// Contains utilties that package the encrypted data et al so that it can be
// stored or sent over a wire, and later retrived and decrypted if the user can
// access the key within some KMS.
//
// The storage format is as follows - all parts are base64 encoded
//
// cipherText.iv.edk.edkContext.hmacCode
//
// *cipherText - the encrypted data - encrypted
// *iv - the initalization vector used when created the ciphertext - so two bobs not the same - not encrypted
// *edk - the key used to encrypt data, this is the encrypted version of the key - for example from AWS generate data key - encrypted
// *edkContext - the context used when the data encryption key was generated. In AWS.generateDataKey this must be passed to decrypt the key, and also used to log in
// *cloud trail audit information - not encrypted. Note the AWS key manager is protected by policies that control who can run decrypt.
//     type: serviceName:resource  (ln-connector:poc1.webshield.io.key.pem)
//     id: none
// *hmacCode -  hmacCode across the cipherText, iv, edk, edkContext. Used to make sure format not tampered with and protects against oracle padding attacks.
//

//
// Create the storage format from passed in params.
//  - cipherText - A Buffer - For convenience will convert non Buffer to a Buffer
//  - iv - a Buffer
/// - edk - a Buffer
//  - edkContext - is a JS object
//  - hmacCode - a Buffer
function convert2StorageFormat(params) {
  'use strict';
  var cipherText;
  assert(params.cipherText, util.format('no cipherText:%j', params)); // can be a string or a Buffer
  assert(params.iv, util.format('no iv:%j', params));
  assert(params.edk, util.format('no edk:%j', params));
  assert(params.edkContext, util.format('no edkContext:%j', params)); // is expected to be a JS object
  assert(params.hmacCode, util.format('no hmac:%j', params)); // expect to be in base64 code already

  if (!(params.cipherText instanceof Buffer)) {
    cipherText = new Buffer(params.cipherText);
  } else {
    cipherText = params.cipherText;
  }

  return cipherText.toString(ENCODING) + '.' + params.iv.toString(ENCODING) + '.' +
        params.edk.toString(ENCODING) + '.' + new Buffer(JSON.stringify(params.edkContext)).toString(ENCODING) + '.' +
        params.hmacCode;  //hmac.digest(ENCODING);
}

//
// Converts from storage format into a object - all data is returned in a Buffer and caller interprets
//
function reverseStorageFormat(sfmt) {
  'use strict';
  var unpack = {}, t;
  t = sfmt.split('.');

  unpack.cipherText = new Buffer(t[0], ENCODING);
  unpack.iv = new Buffer(t[1], ENCODING);

  unpack.edk =  new Buffer(t[2], ENCODING);
  unpack.edkContext =  JSON.parse(new Buffer(t[3], ENCODING).toString()); // fixme add try.catch

  unpack.hmacCode = t[4];

  return unpack;
}

module.exports = {
  convert2StorageFormat: convert2StorageFormat,
  reverseStorageFormat: reverseStorageFormat
};
