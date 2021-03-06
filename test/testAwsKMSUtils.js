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
const assert = require('assert');
const awsKMSUtils = require('../lib/awsKMSUtils');
const util = require('util');

describe('UTILS-AWS utils tests', function () {
  'use strict';

  let kms;

  before(function (done) {
    //
    // Create a KMS connection so can test
    //
    let opts = {};
    opts.kmsOptions = { region: 'us-east-1' };
    kms =  awsKMSUtils.create(opts);
    done();
  });

  describe('1 list CMKs', function () {

    it('1.1 should list customer master keys', function (done) {
      kms.listKeys(function (err, data) {
        assert(!err, util.format('unexpected error on listKeys:%j', err));
        console.log(data);
        done();
      });
    }); // it 1.1
  }); // describe 1

  //
  // Note how have added a well known encryption context to the data key
  // that records information such as service type and an id.
  //
  describe('2 generate a data key using a master key and encryption context that ties key, and then decrypt the data key', function () {

    it('2.1 generate a key and decrypt it', function (done) {
      let genDataKeyOptions = {
        KeyId: 'arn:aws:kms:us-east-1:835222312890:alias/test_out_kms',
        KeySpec: 'AES_256',
        EncryptionContext: {
          type: 'servicename:resourcename',
          id: 'none' }
      };

      kms.generateDataKey(genDataKeyOptions, function (err, data) {
        assert(!err, util.format('unexpected error on genDataKey:%j', err));
        assert(data, 'no data passed back');
        assert(data.CiphertextBlob, util.format('No data.CiphertextBlob:%j', data));
        assert(data.Plaintext, util.format('No data.Plaintext:%j', data));
        assert(data.KeyId, util.format('No data.KeyId:%j', data));
        console.log('*** Encrypted Data Key');
        console.log(data);

        let decryptKeyParams = {};
        decryptKeyParams.CiphertextBlob = data.CiphertextBlob;
        decryptKeyParams.EncryptionContext = genDataKeyOptions.EncryptionContext;
        kms.decryptDataKey(decryptKeyParams, function (err, data2) {
          assert(!err, util.format('unexpected error on genDataKey:%j', err));
          assert(data2, 'no data2 passed back');
          assert((data2.Plaintext.toString('base64') === data.Plaintext.toString('base64')),
              'decrypted key does not match encrypted key');
          console.log('*** Decrypted Data Key');
          console.log(data2);
          done();

        });
      });
    }); // it 2.1
  }); // describe 2

});
