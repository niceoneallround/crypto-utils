/*jslint node: true, vars: true */

// test the aws KMS utils - expects credentials in ~/.aws
//
// Only run tests locally as do not want to put any credentials in
// git or code build. So create two grunt targets one that can be used
// when not running locally and skips this test
//
//
// Test local crypt routines
//
var assert = require('assert'),
    awsKMSUtils = require('../lib/awsKMSUtils'),
    util = require('util');

describe('aws KMS utils tests', function () {
  'use strict';

  var kms;

  before(function (done) {
    var opts = {};
    opts.kmsOptions = { region: 'us-east-1' };
    kms =  awsKMSUtils.create(opts);
    done();
  });

  describe('1 list keys tests', function () {

    it('1.1 should list keys', function (done) {
      kms.listKeys(function (err, data) {
        assert(!err, util.format('unexpected error on listKeys:%j', err));
        assert(data, 'no data passed back');
        console.log(data);
        done();
      });
    }); // it 1.1
  }); // describe 1

  describe('2 generate data key tests', function () {

    it('2.1 generate a key and decrypt it', function (done) {
      var genDataKeyOptions = {
        KeyId: 'arn:aws:kms:us-east-1:835222312890:alias/test_out_kms',
        KeySpec: 'AES_256',
        EncryptionContext: { type: 'servicename:resourcename', id: 'none' }
      };

      kms.generateDataKey(genDataKeyOptions, function (err, data) {
        var decryptKeyParams;
        assert(!err, util.format('unexpected error on genDataKey:%j', err));
        assert(data, 'no data passed back');
        assert(data.CiphertextBlob, util.format('No data.CiphertextBlob:%j', data));
        assert(data.Plaintext, util.format('No data.Plaintext:%j', data));
        assert(data.KeyId, util.format('No data.KeyId:%j', data));
        console.log(data);

        decryptKeyParams = {};
        decryptKeyParams.CiphertextBlob = data.CiphertextBlob;
        decryptKeyParams.EncryptionContext = genDataKeyOptions.EncryptionContext;
        kms.decryptDataKey(decryptKeyParams, function (err, data2) {
          assert(!err, util.format('unexpected error on genDataKey:%j', err));
          assert(data2, 'no data2 passed back');
          assert((data2.Plaintext.toString('base64') === data.Plaintext.toString('base64')),
              'decrypted key does not match encrypted key');
          console.log(data2);
          done();

        });
      });
    }); // it 2.1
  }); // describe 2

});
