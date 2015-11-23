/*jslint node: true, vars: true */
var assert = require('assert'),
    crypto = require('crypto'),
    nodeCryptoUtils = require('./nodeCryptoUtils'),
    formatUtils = require('./formatUtils'),
    VError = require('verror'),
    util = require('util');

//
// routines that utilize the util routines to perform the following
//
// encryptHMACEncode
//  1 encrypt the data
//    1.1 use AWS.KMS to generate a key that can be use for AES-256-CBC, using the passed in master key and passed in key context
//      - As the key context is also logged in the cloud trail audit, a suggested format is
//            type: serviceName:resource
//            id: none
//    1.2 encrypt the data with AES-256 using the key from AWS.KMS and a random IV
//  2 create a SHA256 hmac code across the encrypted data, the iv, the encrypted key, and key context - using the AWS.KMS key
//  3 create the 'encoded' representation that supports decryption and can be stored or sent over the wire, consisting of
//    3.1 It contains the encrypted data, the iv, the encrypted key, the key context, and the hmacCode
//
// decodeHMACDecrypt
//  1 unpack the encoded representation
//  2 Decrypt the key using AWS.KMS and the keyContext
//  3 Recompute the HMAC code and compare with one in the encoded representation. If different stop.
//  4 Decrypt the data
//

//
// The routines takes the following params and genarates a representation of the data that has the following PROPERTIES
// *the data and key are encrypted
// *all the context necessary to decrypt the data is present (encrypted key and iv)
// *is protected from tampering using HMAC - FIXME use the same key for HMAC as data encrypt in future allow to be different
// *is base64 encoded so can be stored or sent over the wire
//
// The passed in parameters are:
// *params
//   **params.kms - the kms connection to use
//   **params.kmsKeyParams - the params to pass to the AWS.generateDatakey - see awsKMSUtils.generateDatakey for details
//   **params.plain - the data to encrypt, either a Buffer or a String
// *next - function(err, sfmt) called on completion
//
// The routine performs the following steps
//
// *request a key from AWS.generateDatakey that can be used for AES256 and SHA256 using the passed in AWS master key Id
// *Encrypt the passed in data using AES256, the key from AWS, and an initialization vector (V) populated with a random value.
// *Generate a base64 representation of the above information that can be stored or sent over the wire, and be protected from tampering
//  **To protect from tampering generate a SHA256 HMAC over
//    ***the based64 encoded encrypted data
//    ***the base64 encoded clear text IV
//    ***the base64 encoded encrypted version of the key
//    ***the base64 encoded clear text key context
//  **To store/send create a base64 encocded string in the following format
//    *** base64_encrypted_data.base64_iv.base64_encrypted_key.base64_key_contex.base64_hmacCode
//
function encryptHMACEncode(params, next) {
  'use strict';
  assert(params.kms, util.format('No params.kms passed in:%j', params));
  assert(params.kmsKeyParams, util.format('No params.kmsKeyParams passed in:%j', params));
  assert(params.kmsKeyParams.EncryptionContext,
        util.format('No params.kmsKeyParams.EncryptionContext passed in:%j', params)); // use context in this routine so check there
  assert(params.plain, util.format('No params.plain passed in:%j', params));

  params.kms.generateDataKey(params.kmsKeyParams, function(err, keyInfo) {
    var sfmt = null, ciphered, hmacCode, iv;
    if (err) {
      return next(err, null);
    }

    assert(keyInfo.Plaintext, util.format('generateDataKey results no keyInfo.Plaintext:%j', keyInfo));
    assert(keyInfo.CiphertextBlob, util.format('generateDataKey results no keyInfo.CiphertextBlob:%j', keyInfo));
    assert(keyInfo.KeyId, util.format('generateDataKey results no keyInfo.KeyId:%j', keyInfo));

    // encrypt the data using the key
    iv = new Buffer(crypto.randomBytes(16)); // generate a new one each time so if cipher same plain they are different.
    ciphered = nodeCryptoUtils.encrypt({
      algorithm: 'AES-256-CBC',
      plain: params.plain,
      key: keyInfo.Plaintext,
      iv: iv
    });

    // generate HMAC code
    hmacCode = nodeCryptoUtils.createHMAC({
      hmacAlgorithm: 'SHA256',
      hmacKey: keyInfo.Plaintext, // use same key that was used to encrypt
      cipherText: ciphered,
      iv: iv,
      cipherKey: keyInfo.CiphertextBlob,
      keyContext: params.kmsKeyParams.EncryptionContext
    });

    // create encoded format
    sfmt = formatUtils.encode({
      cipherText: ciphered,
      iv: iv,
      cipherKey: keyInfo.CiphertextBlob,
      keyContext: params.kmsKeyParams.EncryptionContext,
      hmacCode: hmacCode.digest('base64')
    });

    return next(err, sfmt);
  });
}

// Returns the plain text data from the passed encoded format using the passed in AWS.KMS connection
//
//  - unpack the encoded representation
//  - Decrypt the key using AWS.KMS and the keyContext
//  - Recompute the HMAC code and compare with one in the encoded representation. If different stop.
//  - Decrypt the data
function decodeHMACDecrypt(params, next) {
  'use strict';
  var unpacked, decryptKeyParams;

  assert(params.kms, util.format('No params.kms passed in:%j', params));
  assert(params.sfmt, util.format('No params.sfmt passed in:%j', params));

  // unpack the storage format
  unpacked = formatUtils.decode(params.sfmt);

  // decrypt the key
  decryptKeyParams = {};
  decryptKeyParams.CiphertextBlob = unpacked.cipherKey;
  decryptKeyParams.EncryptionContext = unpacked.keyContext;

  // Assume plain text key has been thrown away but still have encrypted key - decrypt it with AWS and use to de-crypt data locally
  params.kms.decryptDataKey(decryptKeyParams, function(err, keyInfo) {
    var plain, hmac;
    if (err) {
      return next(err, null);
    }

    assert(keyInfo.Plaintext, util.format('decryptDataKey results no keyInfo.Plaintext:%j', keyInfo));
    assert(keyInfo.KeyId, util.format('decryptDataKey results no keyInfo.KeyId:%j', keyInfo));

    // generate HMAC code and compare with one in sfmt
    hmac = nodeCryptoUtils.createHMAC({
      hmacAlgorithm: 'SHA256',
      hmacKey: keyInfo.Plaintext, // use same key that was used to encrypt
      cipherText: unpacked.cipherText,
      iv: unpacked.iv,
      cipherKey: unpacked.cipherKey,
      keyContext: unpacked.keyContext
    });

    // check that not been tampered
    if (!nodeCryptoUtils.compareHMACcode(hmac.digest('base64'), unpacked.hmacCode)) {
      return next(new VError('encoded data was tampered with as hmacCode does not match'), null);
    }

    // all ok so lets decrypt data
    plain = nodeCryptoUtils.decrypt({
        algorithm: 'AES-256-CBC',
        cipherText: unpacked.cipherText,
        key: keyInfo.Plaintext,
        iv: unpacked.iv
      });

    return next(null, plain);
  });

}

module.exports = {
  encryptHMACEncode: encryptHMACEncode,
  decodeHMACDecrypt: decodeHMACDecrypt
};
