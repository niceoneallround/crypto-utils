/*jslint node: true, vars: true */

//
// Test the creation and unpacking of storage format
//
var assert = require('assert'),
    should = require('should'),
    storageFormatUtils = require('../lib/storageFormatUtils'),
    util = require('util');

describe('storage format tests', function() {
  'use strict';

  describe('1 basic positive tests', function() {

    function createCanonParams() {
      var params = {};

      params.cipherText = new Buffer('encrypted data');
      params.iv = new Buffer('random number 11111');
      params.edk = new Buffer('encrypted key');
      params.edkContext = {
        type: 'service-name:resource-name',
        id: 'none'
      };
      params.hmacCode = new Buffer('long hash');

      return params;
    }

    function checkCanonUnpacked(unpacked, params) {
      assert((unpacked.cipherText.toString('utf-8') === params.cipherText.toString('utf-8')),
              util.format('unpacked cipherText:%j does not match original:%j', unpacked.cipherText.toString('utf-8'), params.cipherText.toString('utf-8')));
      assert((unpacked.iv.toString('utf-8') === params.iv.toString('utf-8')),
                util.format('unpacked iv:%j does not match original:%j', unpacked.iv.toString('utf-8'), params.iv.toString('utf-8')));

      assert((unpacked.edk.toString('utf-8') === params.edk.toString('utf-8')),
                    util.format('unpacked edk:%j does not match original:%j', unpacked.edk.toString('utf-8'), params.edk.toString('utf-8')));

      assert(unpacked.edkContext.type === params.edkContext.type,
                    util.format('unpacked id context:%j does not match orginal:%j', unpacked.edkContext, params.edkContext));

      assert(unpacked.edkContext.id === params.edkContext.id,
                    util.format('unpacked type context:%j does not match orginal:%j', unpacked.edkContext, params.edkContext));

      assert((unpacked.hmacCode.toString('utf-8') === params.hmacCode.toString('utf-8')),
                    util.format('unpacked edk:%j does not match original:%j', unpacked.hmacCode.toString('utf-8'), params.hmacCode.toString('utf-8')));
    }

    it('1.1 should create a storage format and then reverse and all should be the same', function() {
      var params = {}, sfmt, unpacked;

      params = createCanonParams();

      sfmt = storageFormatUtils.convert2StorageFormat(params);
      assert((sfmt.length > 0), util.format('Sfmt string is zero length?'));

      unpacked = storageFormatUtils.reverseStorageFormat(sfmt);
      checkCanonUnpacked(unpacked, params);
    });

    it('1.2 should wrap strings with Buffer', function() {
      var params = {}, sfmt, unpacked;

      params = createCanonParams();
      params.cipherText = 'encrypted data'; // overrride so string

      sfmt = storageFormatUtils.convert2StorageFormat(params);
      assert((sfmt.length > 0), util.format('Sfmt string is zero length?'));

      unpacked = storageFormatUtils.reverseStorageFormat(sfmt);
      checkCanonUnpacked(unpacked, params);
    });
  }); // describe 1

});
