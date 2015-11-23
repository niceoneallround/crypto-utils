/*jslint node: true, vars: true */

//
// Test local crypt routines
//
var assert = require('assert'),
    should = require('should'),
    crypto = require('crypto'),
    localCryptoUtils = require('../lib/localCryptoUtils'),
    util = require('util');

describe('local crypto utils tests', function() {
  'use strict';

  var ALGORITHM = 'AES-256-CBC',
      IV = crypto.randomBytes(16),
      KEY = crypto.randomBytes(32); // need 256 bit key for AES-256

  describe('1 basic encrypt/decrypt positive tests', function() {

    it('1.1 should encrypt and decrypt text', function() {
      var PLAIN = 'bob in plain',
          params, encrypted, decrypted;

      params = {};
      params.algorithm = ALGORITHM;
      params.plain = PLAIN;
      params.key = KEY;
      params.iv = IV;
      encrypted = localCryptoUtils.encrypt(params);

      // decrypt
      params = {};
      params.algorithm = ALGORITHM;
      params.cipherText = encrypted;
      params.key = KEY;
      params.iv = IV;

      decrypted = localCryptoUtils.decrypt(params);

      assert((PLAIN === decrypted.toString('utf-8')),
          util.format('Decrypted:%s does not match:%s', decrypted.toString('utf-8'), PLAIN));

    });

    it('1.2 should encrypt and decrypt binary', function() {
      var PLAIN = new Buffer([1, 2, 3], 'binary'),
          params, encrypted, decrypted;

      params = {};
      params.algorithm = ALGORITHM;
      params.plain = PLAIN;
      params.key = KEY;
      params.iv = IV;

      encrypted = localCryptoUtils.encrypt(params);

      // decrypt
      params = {};
      params.algorithm = ALGORITHM;
      params.cipherText = encrypted;
      params.key = KEY;
      params.iv = IV;

      decrypted = localCryptoUtils.decrypt(params);

      assert((PLAIN.toString('binary') === decrypted.toString('binary')),
          util.format('Decrypted:%s does not match:%s', decrypted.toString('utf-8'), PLAIN));

    });
  }); // describe 1

  describe('2 basic HMAC positive tests', function() {

    it('1.1 should create a hmac from cipherText et al', function() {
      var HMAC_ALGORITHM = 'SHA256',
          HMAC_KEY = crypto.randomBytes(32),
          cipherText = 'bogus cipher text',
          iv = crypto.randomBytes(16),
          keyContext = {type: '23', id: 'none'},
          cipherKey = crypto.randomBytes(32),
          hmac1, hmac2, hmac3, params,
          code1, code2, code3;

      params = {};
      params.hmacAlgorithm = HMAC_ALGORITHM;
      params.hmacKey = HMAC_KEY;

      //  check params containing data to run hmac over
      params.cipherText = new Buffer(cipherText);
      params.iv = new Buffer(iv);
      params.cipherKey = new Buffer(cipherKey);
      params.keyContext = keyContext;

      hmac1 = localCryptoUtils.createHMAC(params);
      hmac2 = localCryptoUtils.createHMAC(params);

      // make sure both hmacCodes are the same hmac.digest(ENCODING)
      code1 = hmac1.digest('base64');
      code2 = hmac2.digest('base64');
      assert(localCryptoUtils.compareHMACcode(code1, code2), util.format('hmac codes1 and code2 are not the same?'));

      // modify params and create new hmac
      params.cipherText = new Buffer('another text');
      hmac3 = localCryptoUtils.createHMAC(params);
      code3 = hmac3.digest('base64');

      assert(!localCryptoUtils.compareHMACcode(code1, code3), util.format('hmac code1 and code3 are the same?'));

    }); // describe 2
  });

});
