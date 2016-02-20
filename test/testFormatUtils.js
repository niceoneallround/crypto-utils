/*jslint node: true, vars: true */

//
// Test the creation and unpacking of storage format
//
var assert = require('assert'),
    formatUtils = require('../lib/formatUtils'),
    util = require('util');

describe('encoded format tests', function () {
  'use strict';

  describe('1 basic positive tests', function () {

    function createCanonParams() {
      var params = {};

      params.cipherText = new Buffer('encrypted data');
      params.iv = new Buffer('random number 11111');
      params.cipherKey = new Buffer('encrypted key');
      params.keyContext = {
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

      assert((unpacked.cipherKey.toString('utf-8') === params.cipherKey.toString('utf-8')),
                    util.format('unpacked cipherKey:%j does not match original:%j', unpacked.cipherKey.toString('utf-8'), params.cipherKey.toString('utf-8')));

      assert(unpacked.keyContext.type === params.keyContext.type,
                    util.format('unpacked type keyContext:%j does not match orginal:%j', unpacked.keyContext, params.keyContext));

      assert(unpacked.keyContext.id === params.keyContext.id,
                    util.format('unpacked id context:%j does not match orginal:%j', unpacked.keyContext, params.keyContext));

      assert((unpacked.hmacCode.toString('utf-8') === params.hmacCode.toString('utf-8')),
                    util.format('unpacked edk:%j does not match original:%j', unpacked.hmacCode.toString('utf-8'), params.hmacCode.toString('utf-8')));
    }

    it('1.1 should create a encoded format and then reverse and all should be the same', function () {
      var params = {}, sfmt, unpacked;
      params = createCanonParams();

      sfmt = formatUtils.encode(params);
      assert((sfmt.length > 0), util.format('Sfmt string is zero length?'));

      unpacked = formatUtils.decode(sfmt);
      checkCanonUnpacked(unpacked, params);
    });

    it('1.2 should wrap strings with Buffer', function () {
      var params = {}, sfmt, unpacked;
      params = createCanonParams();
      params.cipherText = 'encrypted data'; // overrride so string

      sfmt = formatUtils.encode(params);
      assert((sfmt.length > 0), util.format('Sfmt string is zero length?'));

      unpacked = formatUtils.decode(sfmt);
      checkCanonUnpacked(unpacked, params);
    }); // 1.2

    it('1.3 should handle encoded format passed as a Buffer', function () {
        var params = {}, sfmt, unpacked;
        params = createCanonParams();
        params.cipherText = 'encrypted data'; // overrride so string

        sfmt = formatUtils.encode(params);
        assert((sfmt.length > 0), util.format('Sfmt string is zero length?'));

        unpacked = formatUtils.decode(new Buffer(sfmt));
        checkCanonUnpacked(unpacked, params);
      }); // 1.3
  }); // describe 1

});
