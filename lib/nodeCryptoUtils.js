/*jslint node: true, vars: true */

// Contains convenience routines for calling node crypto routines to
// encrypt, decrypt and generate hmacs. Its is influenced by what was
// needed for AES and AWS KMS, hence not designed to be generic.
//
// The encrypt/decrypt routines assume an algorithm that requires a key and IV.
// The hmac is across the the cipherText, iv, the encrypted key, and a key context.

var assert = require('assert'),
    crypto = require('crypto'),
    util = require('util');

//
// locally encrypt data passed in a Buffer returning a Buffer with ciphertext
//
// params.algorithm - the algorithm to use, for example 'AES-256-CBC';
// params.plain - Buffer to encrypt
// params.key - the key to use - a string
// params.iv - the initalization vector to use - a Buffer
//
function encrypt(params) {
  'use strict';
  var cipher, ciphered;
  assert(params.algorithm, util.format('no params.algorithm:%j', params));
  assert(params.plain, util.format('no params.plain:%j', params));
  assert(params.key, util.format('no params.key:%j', params));
  assert(params.iv, util.format('no params.iv:%j', params));

  cipher = crypto.createCipheriv(params.algorithm, params.key, params.iv);
  ciphered = [cipher.update(params.plain)];
  ciphered.push(cipher.final());
  ciphered = Buffer.concat(ciphered);

  return ciphered;
}

//
// locally decrypt data returning a buffer with ciphertext
//
// params.algorithm - the algorithm to use, for example 'AES-256-CBC';
// params.cipherText - Buffer to decrypt
// params.key - the key that was used to encrypt
// params.iv - the initalization vector that was used to encrypt
//
function decrypt(params) {
  'use strict';
  var decipher, deciphered;
  assert(params.algorithm, util.format('no params.algorithm:%j', params));
  assert(params.cipherText, util.format('no params.plain:%j', params));
  assert(params.key, util.format('no params.key:%j', params));
  assert(params.iv, util.format('no params.iv:%j', params));

  decipher = crypto.createDecipheriv(params.algorithm, params.key, params.iv);
  deciphered = [decipher.update(params.cipherText)];
  deciphered.push(decipher.final());
  deciphered = Buffer.concat(deciphered);

  return deciphered;
}

//
// Create a nodeJS HMAC across the properties described below, the caller can
// use the passed back hmac to generate a hmacCode that can be used to authenticate that the data has not been tampered with.
//
// The hmac has the following control parameters
// hmacAlgorithm - what algorithm to use, for example 'SHA256'
// hmacKey - what key to use, needs to align with algorithm
//
// The hmac is made up of the following parts - all are base64 encoded.
// cipherText - the encrypted data - a Buffer
// iv - the initalization vector used when encrypting the data - A Buffer
// cipherKey - the encrypted version of the key used to encrypt the data - A Buffer
// keyContext - context used when requesting the key from a Key Management System such as AWS.KMS - A JS object
//
// Each Buffer/JS Object is converted to a string using base64 encoding
//
function createHMAC(params) {
  'use strict';
  var hmac,
      HMAC_ENCODING = 'base64';

  // check params needed to create HMAC exist
  assert(params.hmacAlgorithm, util.format('no hmacAlgorithm:%j', params));
  assert(params.hmacKey, util.format('no hmacKey:%j', params));

  //  check params containing data to run hmac over
  assert(params.cipherText, util.format('no params.cipherText:%j', params));
  assert(params.iv, util.format('no params.iv:%j', params));
  assert(params.cipherKey, util.format('no params.cipherKey:%j', params)); // encrypted version
  assert(params.keyContext, util.format('no params.keyContext:%j', params)); // encrypted version

  hmac = crypto.createHmac(params.hmacAlgorithm, params.hmacKey);
  hmac.update(params.cipherText.toString(HMAC_ENCODING));
  hmac.update(params.iv.toString(HMAC_ENCODING));
  hmac.update(params.cipherKey.toString(HMAC_ENCODING));
  hmac.update(params.keyContext.toString(HMAC_ENCODING));

  return hmac;

}

// compare two hmac codes to see if the same
function compareHMACcode(code1, code2) {
  'use strict';
  var sentinel, i;

  if (code1.length !== code2.length) {
    return false;
  }

  for (i = 0; i <= (code1.length - 1); i++) {
    sentinel |= code1.charCodeAt(i) ^ code2.charCodeAt(i);
  }

  return sentinel === 0;
}

module.exports = {
  createHMAC: createHMAC,
  compareHMACcode: compareHMACcode,

  encrypt: encrypt,
  decrypt: decrypt
};
