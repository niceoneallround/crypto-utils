/*jslint node: true, vars: true */

// test the encrypt and create storage format, and the reverse
//
// expects credentials in ~/.aws
//
var assert = require('assert'),
    cryptoUtils = require('../lib/cryptoUtils'),
    fs = require('fs'),         // required to read certs and keys
    should = require('should'),
    path = require('path'),
    util = require('util');

describe('Crypto Utils Tests', function() {
  'use strict';

  var kms;

  before(function(done) {
    var params = {};
    params.region = 'us-east-1';
    kms = cryptoUtils.createKMSConnection(params);
    done();
  });

  describe('1 encrypt/hmac/encode - decode/checkHmac/decrypt tests', function() {

    it('1.1 Test with TEXT', function(done) {
      var params = {};
      params.kms = kms;
      params.KeyId = 'arn:aws:kms:us-east-1:835222312890:alias/test_out_kms';
      params.EncryptionContext =  {type: 'servicename:resourcename', id: 'none'};
      params.plain = 'bob';

      cryptoUtils.encryptHMACEncode(params, function(err, sfmt) {
        var decryptParams = {};
        assert(!err, util.format('unexpected error:%j', err));
        assert(sfmt, 'no storage format returned');

        decryptParams.kms = kms;
        decryptParams.sfmt = sfmt;
        cryptoUtils.decodeHMACDecrypt(decryptParams, function(err, plain) {
          var pt;
          assert(!err, util.format('unexpected error:%j', err));
          assert(plain, 'no plain returned');
          pt = plain.toString('utf-8');
          assert((pt === 'bob', util.format('Unecrypted data is not bob:%j', pt)));
          done();
        });
      });
    }); // it 1.1

    it('1.2 Test with Binary', function(done) {
      var params = {}, dataFile, dataBuffer, startJson;
      params.kms = kms;
      params.KeyId = 'arn:aws:kms:us-east-1:835222312890:alias/test_out_kms';
      params.EncryptionContext =  {type: 'servicename:resourcename', id: 'none'};

      dataFile = path.join(__dirname, './testData.json');
      dataBuffer = fs.readFileSync(dataFile); // returns raw buffer of file in binary encoding of file
      params.plain = dataBuffer;
      startJson = JSON.parse(dataBuffer);

      cryptoUtils.encryptHMACEncode(params, function(err, sfmt) {
        var decryptParams = {};
        assert(!err, util.format('unexpected error:%j', err));
        assert(sfmt, 'no storage format returned');

        decryptParams.kms = kms;
        decryptParams.sfmt = sfmt;
        cryptoUtils.decodeHMACDecrypt(decryptParams, function(err, plain) {
          var endJson;
          assert(!err, util.format('unexpected error:%j', err));
          assert(plain, 'no plain returned');
          endJson = JSON.parse(plain);
          endJson.should.have.property('prop1', startJson.prop1);
          done();
        });
      });
    }); // it 1.1
  }); // describe 1

});
