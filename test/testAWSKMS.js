/*jslint node: true, vars: true */

// Learn AWS KMS interfaces

const assert = require('assert');
const AWS = require('aws-sdk');
const util = require('util');

// used when encrypting data locally with an AWS generated key
const crypto = require('crypto');
const nodeCryptoUtils = require('../lib/nodeCryptoUtils');

describe('AWS-KMS utils tests', function () {
  'use strict';

  let kms;

  before(function (done) {
    //
    // Create a KMS connection so can test
    //
    let opts = { region: 'us-east-1', };
    kms = new AWS.KMS(opts);
    done();
  });

  describe('1 list CMKs, Describe Keys', function () {

    it('1.1 should list customer master keys', function (done) {
      kms.listKeys(function (err, data) {
        assert(!err, util.format('unexpected error on listKeys:%j', err));
        console.log('**** lisy keys');
        console.log(data);
        done();
      });
    }); // it 1.1

    it('1.2 describe a customer master keys', function (done) {
      let params = { KeyId: 'arn:aws:kms:us-east-1:835222312890:alias/test_out_kms', };

      kms.describeKey(params, function (err, data) {
        assert(!err, util.format('unexpected error on describeKey:%j', err));
        console.log('*** describe a key');
        console.log(data);
        done();
      });
    }); // it 1.1
  }); // describe 1

  describe('2 Use a Customer Master Key to encrypt/decrypt Data - model a PN client creating a master key for each consumer', function () {

    //
    // An example might be Acme may be sharing data with Company A and Company B
    //
    // To control access, Acme wants to create a CMK per Company, and then define
    // access polices for each company.
    //
    // At encrypt time, need to know the destination so can select the correct
    // CMK. Think about how to model that.
    //

    it('2.1 should encrypt and decrypt data using a CMK', function (done) {

      // to encrypt need to know
      // 1. The KMS region - comes from the KMS
      // 2. The customer master key to use for destination resource ID.
      // 3. Encryption Context for this field
      let encryptParams = {
        KeyId: 'arn:aws:kms:us-east-1:835222312890:alias/test_out_kms',
        Plaintext: 'field-2-encrypt',
        EncryptionContext: {
          id: 'https://id.webshield.io/com/acme/person#bob'
        },
      };

      kms.encrypt(encryptParams, function (err, data) {
        assert(!err, util.format('unexpected error on encrypt:%j', err));
        console.log('*** Encrypted Data using CMK:%s', encryptParams.KeyId);
        console.log(data);
        console.log('Encrypted data using CMK:%j', data);
        data.should.have.property('CiphertextBlob');
        data.should.have.property('KeyId');

        //
        // Lets decrypt the data needs the following information
        // 1. The Ciphertext Blob from the encryption request
        // 2. The AAD that was used when encrypting.
        //
        // Need to understand the KMS region
        //
        let decryptParams = {
          CiphertextBlob: data.CiphertextBlob,
          EncryptionContext: encryptParams.EncryptionContext,
        };

        kms.decrypt(decryptParams, function (err, data2) {
          assert(!err, util.format('unexpected error on decrypt:%j', err));
          console.log('*** Decrypted Data using CMK');
          console.log(data2);
          console.log('Decrypted data using CMK:%j', data2);
          data2.should.have.property('Plaintext');
          data2.should.have.property('KeyId');
          console.log('Decrypted decoded data:%s', data2.Plaintext.toString());
          done();
        });
      });
    }); // it 2.1
  }); // describe 2

  //
  // Note how have added a well known encryption context to the data key
  // that records information such as service type and an id.
  //
  describe('3 generate a data key using a master key and encryption context that ties key, and then decrypt the data key', function () {

    //
    // To generate the data key, this returns the encrypted key and the plaintext key
    // 1. KMS region
    // 2. Master Key to use to generate a data key to return to this resource Id
    // 3. The Key Spec - from privacy algorithm
    // 4. Encryption Context - for example could be the destination resourceId
    //
    it('3.1 generate a key and decrypt it', function (done) {
      let genDataKeyOptions = {
        KeyId: 'arn:aws:kms:us-east-1:835222312890:alias/test_out_kms',
        KeySpec: 'AES_256',
        EncryptionContext: {
          type: 'servicename:resourcename',
          id: 'none' }
      };

      kms.generateDataKey(genDataKeyOptions, function (err, data) {
        assert(!err, util.format('unexpected error on genDataKey:%j', err));
        console.log('*** Encrypted Data Key');
        console.log(data);
        data.should.have.property('CiphertextBlob');
        data.should.have.property('KeyId');
        data.should.have.property('Plaintext');

        //
        // lets use the plain text data key to encrypt some data use the node crypto wrapper
        //
        let savedIV = crypto.randomBytes(16);
        let params = {
          algorithm: 'AES-256-CBC',
          plain: 'field-2-encrypt',
          key: data.Plaintext,
          iv: savedIV,
        };

        let encryptedData = nodeCryptoUtils.encrypt(params);
        console.log('*** Encrypted Data using the AWS generated data Key');
        console.log(encryptedData);

        //
        // To decrypt the data, need to first decrypt the data key and then the data
        // 1. The encrypted data key
        // 2. To decrypt the data key need
        // 2.1  The KMS that was used to encrypt the data key
        // 2.2  The CMK that was used to encrypt the key
        let decryptKeyParams = {};
        decryptKeyParams.CiphertextBlob = data.CiphertextBlob;
        decryptKeyParams.EncryptionContext = genDataKeyOptions.EncryptionContext;
        kms.decrypt(decryptKeyParams, function (err, data2) {
          assert(!err, util.format('unexpected error on genDataKey:%j', err));
          assert(data2, 'no data2 passed back');
          assert((data2.Plaintext.toString('base64') === data.Plaintext.toString('base64')),
              'decrypted key does not match encrypted key');
          console.log('*** Decrypted Data Key');
          console.log(data2);

          //
          // Use the decrypted data key to make sure we can decrypt the data we
          // encrypted with the key
          let params = {
            algorithm: 'AES-256-CBC',
            cipherText: encryptedData,
            key: data2.Plaintext,
            iv: savedIV,
          };

          let decryptedData = nodeCryptoUtils.decrypt(params);
          console.log('*** Encrypted Data using decrypted AWS data Key');
          console.log(decryptedData);
          console.log('Decrypted decoded data:%s', decryptedData.toString());
          done();

        });
      });
    }); // it 3.1
  }); // describe 3

});
