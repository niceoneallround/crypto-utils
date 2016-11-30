/*jslint node: true, vars: true */

const assert = require('assert');
const AWS = require('aws-sdk');
const util = require('util');

// Light Weight Wrappers to KMS routines
//
// Credentials - If not running in an AWS environment then picked up from ~/.aws
//

// factory routine to create AWS KMS connection
// *options.kmsOptions - a direct mapping to AWS.KMS params see http://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/KMS.html
//
function create(options) {
  'use strict';
  assert(options.kmsOptions, 'no options.kmsOptions');

  let kms = new AWS.KMS(options.kmsOptions);

  // list master keys witin the region
  function listKeys(next) {
    kms.listKeys({}, function (err, data) {
      if (!err) {
        return next(null, data);
      } else {
        return next(err);
      }
    });
  } // list keys

  // generate a data key from a master key
  function generateDataKey(AWSparams, next) {
    assert(AWSparams.KeyId, util.format('no AWSparams.KeyId: %j', AWSparams));
    assert(AWSparams.KeySpec, util.format('no AWSparams.KeySpec: %j', AWSparams));
    assert(AWSparams.EncryptionContext, util.format('no AWSparams.EncryptionContext: %j', AWSparams));

    kms.generateDataKey(AWSparams, function (err, data) {
      return next(err, data);
    });
  } // genDataKey

  // decrypt an encrypted key
  function decryptDataKey(AWSparams, next) {
    assert(AWSparams.CiphertextBlob, util.format('No AWSparams.CiphertextBlob:%j', AWSparams));
    assert(AWSparams.EncryptionContext, util.format('No AWSparams.EncryptionContext:%j', AWSparams));
    kms.decrypt(AWSparams, function (err, data) {
      return next(err, data);
    });
  } // decryptKey

  return {
    listKeys: listKeys,
    generateDataKey: generateDataKey,
    decryptDataKey: decryptDataKey };

} // create

module.exports = {
  create: create
};
