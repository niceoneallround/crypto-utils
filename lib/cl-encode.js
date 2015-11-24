#!/usr/bin/env node
/*jslint node: true, vars: true */
/* jscs:disable */ // as have underscores in name
'use strict';

var assert = require('assert'),
  awsKMSUtils = require('./awsKMSUtils'),
  commander = require('commander'),
  cryptoUtils = require('./cryptoUtils'),
  dataBuffer,
  fs = require('fs'),
  kms,
  util = require('util');

//
// Command line tool for generating the encoded format from a set of command line params and displaying to stdout
//
commander
  .version('1.0.0')
  .option('-a, --aws_access_key_id <file>', 'the AWS credential aws_access_key_id. If not specified uses default in ~/.aws/credentials')
  .option('-c, --aws_encryption_context <file>', 'the json format AWS key context to pass in when generating the data key from the master key')
  .option('-i, --in <file>', 'file containing the data to encrypt')
  .option('-k, --aws_master_key <keyid>', 'the AWS master key to use when generating the key')
  .option('-r, --aws_region <region>', 'the AWS region containing the master key')
  .option('-s, --aws_secret_access_key <secret>', 'the AWS credential aws_secret_access_key. If not specified uses default in ~/.aws/credentials')
  .parse(process.argv);

// read the file to encrypt
assert(commander.in, util.format('Must specifiy an input file to encrypt with -i: %s', process.argv));
console.log('Input file:%s', commander.in);
dataBuffer = fs.readFileSync(commander.in); // returns raw buffer of file in binary encoding of file

// deal with credentials if passed in
assert(!commander.aws_access_key_id, util.format('cannot yet handle aws_access_key_id'));
assert(!commander.aws_secret_access_key, util.format('cannot yet handle aws_secret_access_key'));

// create a KMS connection using the kms options passed in
assert(commander.aws_region, util.format('Must specifiy an AWS region with -r: %s', process.argv));
console.log('AWS region:%s', commander.aws_region);

kms =  awsKMSUtils.create({
  kmsOptions: {
    region: commander.aws_region
  }
});
assert(kms, 'No KMS connection created');

assert(commander.aws_master_key, util.format('Must specifiy an AWS Master Key with -k: %s', process.argv));
console.log('AWS master key:%s', commander.aws_master_key);
assert(commander.aws_encryption_context, util.format('Must specifiy an AWS Key Context with -c: %s', process.argv));
console.log('AWS encryption context:%j', JSON.parse(commander.aws_encryption_context));
cryptoUtils.encryptHMACEncode(
  {
    kms: kms,
    KeyId: commander.aws_master_key,
    EncryptionContext: JSON.parse(commander.aws_encryption_context),
    plain: dataBuffer
  },
  function(err, result) {
    assert(!err, util.format('Unexpected error:%j', err));
    console.log('Result is:');
    console.log(result);
});
