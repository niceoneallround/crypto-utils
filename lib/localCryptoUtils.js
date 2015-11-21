/*jslint node: true, vars: true */

// Contains convenience routines for calling node crypto routines

var assert = require('assert'),
    crypto = require('crypto'),
    util = require('util');

// use CBC as want to add the random Ib to each encryption
//ALGORITHM = 'AES-256-CBC', // look at what one to choose
// now generate KEY = crypto.randomBytes(32); // need 256 bit key for AES-256
//HMAC_ALGORITHM = 'SHA256',
//HMAC_KEY = crypto.randomBytes(32), // need 256 bit key for SHA256
//HMAC_ENCODING = 'base64',

//
// locally encrypt data passed in a Buffer returning a Buffer with ciphertext
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

// Used to authenticate that the stored data has not been tampered with
//
// The hmac has the following control parameters
// hmacAlgorithm - what algorithm to use, for example 'SHA256'
// hmacKey - what key to use, needs to align with algorithm
//
// The hmac is made up of the following parts
// cipherText - a Buffer
// iv - A Buffer
// edk - A Buffer
// edkContext - A JS object
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
  assert(params.cipherText, util.format('no cipherText:%j', params));
  assert(params.iv, util.format('no iv:%j', params));
  assert(params.edk, util.format('no edk:%j', params)); // encrypted version
  assert(params.edkContext, util.format('no edkContext:%j', params)); // encrypted version

  hmac = crypto.createHmac(params.hmacAlgorithm, params.hmacKey);
  hmac.update(params.cipherText.toString(HMAC_ENCODING));
  hmac.update(params.iv.toString(HMAC_ENCODING));
  hmac.update(params.edk.toString(HMAC_ENCODING));
  hmac.update(params.edkContext.toString(HMAC_ENCODING));

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
