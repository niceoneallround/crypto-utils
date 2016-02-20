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

describe('Crypto Utils Tests', function () {
  'use strict';

  var kms,
      KEY_ID = 'arn:aws:kms:us-east-1:835222312890:alias/test_out_kms',
      E_CONTEXT =   { type: 'servicename:resourcename', id: 'none' };

  before(function (done) {
    kms = cryptoUtils.createKMSConnection({ region:'us-east-1' });
    done();
  });

  describe('1 encrypt/hmac/encode - decode/checkHmac/decrypt tests', function () {

    it('1.1 Test with TEXT', function (done) {
      var params = {};
      params.kms = kms;
      params.KeyId = KEY_ID;
      params.EncryptionContext =  E_CONTEXT;
      params.plain = 'bob';

      cryptoUtils.encryptHMACEncode(params, function (err, sfmt) {
        var decryptParams = {};
        assert(!err, util.format('unexpected error:%j', err));
        assert(sfmt, 'no storage format returned');

        decryptParams.kms = kms;
        decryptParams.sfmt = sfmt;
        cryptoUtils.decodeHMACDecrypt(decryptParams, function (err, plain) {
          var pt;
          assert(!err, util.format('unexpected error:%j', err));
          assert(plain, 'no plain returned');
          pt = plain.toString('utf-8');
          assert((pt === 'bob', util.format('Unecrypted data is not bob:%j', pt)));
          done();
        });
      });
    }); // it 1.1

    it('1.2 Test with Binary', function (done) {
      var params = {}, dataFile, dataBuffer;
      params.kms = kms;
      params.KeyId = KEY_ID;
      params.EncryptionContext =  E_CONTEXT;

      dataFile = path.join(__dirname, './testData.plain');
      dataBuffer = fs.readFileSync(dataFile); // returns raw buffer of file in binary encoding of file
      params.plain = dataBuffer;
      cryptoUtils.encryptHMACEncode(params, function (err, sfmt) {
        var decryptParams = {};
        assert(!err, util.format('unexpected error:%j', err));
        assert(sfmt, 'no storage format returned');

        decryptParams.kms = kms;
        decryptParams.sfmt = sfmt;
        cryptoUtils.decodeHMACDecrypt(decryptParams, function (err, plain) {
          var endJson, startJson;
          assert(!err, util.format('unexpected error:%j', err));
          assert(plain, 'no plain returned');
          startJson = JSON.parse(dataBuffer);
          endJson = JSON.parse(plain);
          endJson.should.have.property('prop1', startJson.prop1);
          done();
        });
      });
    }); // it 1.2

    it('1.3 Test when encoded format is a buffer', function (done) {
      var params = {};
      params.kms = kms;
      params.KeyId = KEY_ID;
      params.EncryptionContext =  E_CONTEXT;
      params.plain = 'bobby';

      cryptoUtils.encryptHMACEncode(params, function (err, sfmt) {
        var decryptParams = {};
        assert(!err, util.format('unexpected error:%j', err));
        assert(sfmt, 'no storage format returned');

        decryptParams.kms = kms;
        decryptParams.sfmt = new Buffer(sfmt);
        cryptoUtils.decodeHMACDecrypt(decryptParams, function (err, plain) {
          assert(!err, util.format('unexpected error:%j', err));
          assert(plain, 'no plain returned');
          assert((plain === 'bobby', util.format('Unecrypted data is not bobby:%j', plain)));
          done();
        });
      });
    }); // it 1.3

    it('1.4 Read encoded file and make sure matches plain text file', function (done) {
      var encodedFile, encodedBuffer, decryptParams = {};
      encodedFile = path.join(__dirname, './testData.encoded');
      encodedBuffer = fs.readFileSync(encodedFile);

      decryptParams.kms = kms;
      decryptParams.sfmt = encodedBuffer;

      cryptoUtils.decodeHMACDecrypt(decryptParams, function (err, plain) {
        assert(!err, util.format('unexpected error:%j', err));
        assert(plain, 'no plain returned');
        done();
      });
    }); // it 1.4
  }); // describe 1

});
