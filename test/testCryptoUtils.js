/*jslint node: true, vars: true */

// test the encrypt and create storage format, and the reverse
//
// expects credentials in ~/.aws
//
var assert = require('assert'),
    awsKMSUtils = require('../lib/awsKMSUtils'),
    cryptoUtils = require('../lib/cryptoUtils'),
    util = require('util');

describe('Crypto Utils Tests', function() {
  'use strict';

  var kms;

  before(function(done) {
    var opts = {};
    opts.kmsOptions = { region: 'us-east-1'};
    kms =  awsKMSUtils.create(opts);
    done();
  });

  describe('1 Encrypt/MakeStoreFormat/Reverse/Decrypt tests', function() {

    it('1.1 Encrypt text and convert to storage format, then reverse and decrypt', function(done) {
      var params = {};

      params.kms = kms;
      params.kmsKeyParams = {
        KeyId: 'arn:aws:kms:us-east-1:835222312890:alias/test_out_kms',
        KeySpec: 'AES_256',
        EncryptionContext: {type: 'servicename:resourcename', id: 'none'}
      };
      params.plain = 'bob';

      cryptoUtils.encryptHMACConvert2StorageFormat(params, function(err, sfmt) {
        var decryptParams = {};
        assert(!err, util.format('unexpected error:%j', err));
        assert(sfmt, 'no storage format returned');

        decryptParams.kms = kms;
        decryptParams.sfmt = sfmt;
        cryptoUtils.reverseStorageCheckHMACDecrypt(decryptParams, function(err, plain) {
          var pt;
          assert(!err, util.format('unexpected error:%j', err));
          assert(plain, 'no plain returned');
          pt = plain.toString('utf-8');
          assert((pt === 'bob', util.format('Unecrypted data is not bob:%j', pt)));
          done();
        });
      });
    }); // it 2.1
  }); // describe 2

});
