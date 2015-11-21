/*jslint node: true, vars: true */
var assert = require('assert'),
    AWS = require('aws-sdk'),
    crypto = require('crypto'),
    kmsOptions, kms, genDataKeyOptions, encryptDataOptions, dataKey,
    s3Options, s3,
    fs = require('fs'),         // required to read certs and keys
    path = require('path'),
    privateKeyFile = path.join(__dirname, './server.key.pem'),
    privateKey = fs.readFileSync(privateKeyFile), // returns raw buffer of file in binary encoding of file
    util = require('util'),
    // use CBC as want to add the random Ib to each encryption
    ALGORITHM = 'AES-256-CBC', // look at what one to choose
    // now generate KEY = crypto.randomBytes(32); // need 256 bit key for AES-256
    //HMAC_ALGORITHM = 'SHA256',
    //HMAC_KEY = crypto.randomBytes(32), // need 256 bit key for SHA256
    //HMAC_ENCODING = 'base64',
    ENCODING = 'base64',
    EDK_CONTEXT = {
      type: 'ln-connector:poc1.webshield.io.key.pem',
      id: 'none'
    };

//
// The format is as follows
//
// cipherText.initializationVector.edk.edkContext.hmacCode
//
// cipherText - the encrypted data - encrypted
// IV - the initalization vector used when created the ciphertext - so two bobs not the same - not encrypted
// edk - the key used to encrypt data, this is the encrypted version of the key - for example from AWS generate data key - encrypted
// edkContext - the context used when the data encryption key was generated. In AWS.generateDataKey this must be passed to decrypt the key, and also used to log in
// cloud trail audit information - not encrypted. Note the AWS key manager is protected by policies that control who can run decrypt.
//     type: serviceName:resource  (ln-connector:poc1.webshield.io.key.pem)
//     id: none
//
// hmacCode -  hmacCode across the cipherText, iv, edk, edkContext. Used to make sure format not tampered with and protects against oracle padding attacks. Only decrypt if not been tampered with. Use same key as for data so data encryption and hmac need to be the same format.
//
function createStorageFormat(params) {
  assert(params.cipherText, util.format('no cipherText:%j', params));
  assert(params.iv, util.format('no iv:%j', params));
  assert(params.edk, util.format('no edk:%j', params));
  assert(params.edkContext, util.format('no edkContext:%j', params));
  assert(params.hmac, util.format('no hmac:%j', params));

  return params.cipherText.toString(ENCODING) + '.' + params.iv.toString(ENCODING) + '.' +
        params.edk.toString(ENCODING) + '.' + new Buffer(JSON.stringify(params.edkContext)).toString(ENCODING) + '.' +
        params.hmac.digest(ENCODING);
}

// Converts from storage format into a object
function reverseStorageFormat(sfmt) {
  var unpack = {}, t;
  t = sfmt.split(".");
  unpack.cipherText = new Buffer(t[0], ENCODING)
  unpack.iv = new Buffer(t[1], ENCODING);

  unpack.edk =  new Buffer(t[2], ENCODING);
  unpack.edkContext =  JSON.parse(new Buffer(t[3], ENCODING).toString()); // fixme add try.catch

  unpack.hmacCode = t[4];

  return unpack;
}

// Used to authenticate that the stored data has not been tampered with
//
// The hmac has the following control parameters
// hmacAlgorithm - what algorithm to use, for example 'SHA256'
// hmacKey - what key to use, needs to align with algorithm
//
// The hmac is made up of the following parts, that are each passed as a Buffer.
// Each Buffer is converted to a string using base64 encoding
//
function createHMAC(params) {
  var hmac,
      HMAC_ENCODING = 'base64';
  // check params needed to create HMAC exist
  assert(params.hmacAlgorithm, util.format('no hmacAlgorithm:%j', params));
  assert(params.hmacKey, util.format('no hmacKey:%j', params));

  //  check params containing data to run hmac over
  assert(params.cipherText, util.format('no cipherText:%j', params));
  assert(params.iv, util.format('no iv:%j', params));
  assert(params.edk, util.format('no edk:%j', params)); // encrypted version
  assert(params.edkContext, util.format('no edkContext:%j', params)); // encrypted version

  hmac = crypto.createHmac(params.hmacAlgorithm, params.hmacKey);
  hmac.update(params.cipherText.toString(HMAC_ENCODING));
  hmac.update(params.iv.toString(HMAC_ENCODING));
  hmac.update(params.edk.toString(HMAC_ENCODING));
  hmac.update(params.edkContext.toString(HMAC_ENCODING));

  return hmac;

}

//AWS.config.update(options);

// no region as global
/*s3Options = {
  sslEnabled: false
};
s3 = new AWS.S3(s3Options);
s3.listBuckets({}, function(err, data) {
  if (!err) {
    console.log(data);
  } else {
    console.log(err, err.stack); // an error occurred
  }
});*/

kmsOptions = {
  region: 'us-east-1'
};
kms = new AWS.KMS(kmsOptions);

// list aliases
//http://docs.aws.amazon.com/general/latest/gr/rande.html#kms_region
function listAliases(next) {
  kms.listAliases({}, function(err, data) {
    if (!err) {
      console.log(data);
      return next();
    } else {
      console.log(err, err.stack); // an error occurred
    }
  });
}

function listKeys(next) {
  kms.listKeys({}, function(err, data) {
    if (!err) {
      console.log(data);
      return next();
    } else {
      console.log(err, err.stack); // an error occurred
    }
  });
}

function AWSgenAES256DataKey(next) {

  genDataKeyOptions = {
    KeyId: 'arn:aws:kms:us-east-1:835222312890:alias/test_out_kms',
    KeySpec: 'AES_256',
    EncryptionContext: EDK_CONTEXT
  };

  kms.generateDataKey(genDataKeyOptions, function(err, data) {
    if (!err) {
      //console.log(data);
      console.log('AWS - Ciphertext-key: %j', data.CiphertextBlob);
      console.log('AWS - Plaintext-key: %j', data.Plaintext);
      console.log('AWS - Master-KeyId: %j', data.KeyId);
      return next(err, data);
    } else {
      console.log(err, err.stack); // an error occurred
    }
  });
}

function AWSdecryptKey(AWSparams, next) {
  var opts = {};

  assert(AWSparams.CiphertextBlob, util.format('No AWSparams.CiphertextBlob:%j', AWSparams));
  assert(AWSparams.EncryptionContext, util.format('No AWSparams.EncryptionContext:%j', AWSparams));
  kms.decrypt(AWSparams, function(err, data) {
    if (!err) {
      console.log('AWS - Decrypted - PlaintextKey:%j', data.Plaintext);
      next(err, data);
    } else {
      console.log(err, err.stack); // an error occurred
    }

  });
}

//
// locally encrypt data returning a buffer with ciphertext
// params.plain - Buffer to encrypt
// params.inputEncoding - optional input encoding for text
// params.outputEncoding - optional output encoding for cipher
// params.key - the key to use
// params.iv - the initalization vector to use
//
function encrypt(params) {
  var cipher, ciphered;
  assert(params.plain, util.format('no params.plain:%j', params));
  assert(params.key, util.format('no params.key:%j', params));
  assert(params.iv, util.format('no params.iv:%j', params));

  cipher = crypto.createCipheriv(ALGORITHM, params.key, params.iv);
  /*if (params.inputEncoding) {
    cipher.setEncoding(params.inputEncoding);
  }
  cipher.write(params.plain);*/
  ciphered = [cipher.update(params.plain)];//, params.inputEncoding, params.outputEncoding);
  ciphered.push(cipher.final());
  ciphered = Buffer.concat(ciphered);

  console.log('Encrypted: %j', ciphered.toString(ENCODING));

  return ciphered;
}

// edkInfo
function encryptHMACConvert2StorageFormat(params, edkInfo) {
  var cipher, hmac, cipherText,
      // make initialization vector random - should geneated a new one each time so if cipher bob and hen bob again are diffrent
      IV = new Buffer(crypto.randomBytes(16));

  assert(edkInfo.plainText, util.format('no edkInfo.plainText:%j', edkInfo));
  assert(edkInfo.cipherText, util.format('no edkInfo.cipherText:%j', edkInfo));
  assert(edkInfo.context, util.format('no edkInfo.context:%j', edkInfo));

  cipherText = encrypt(
    { plain: params.plain,
      inputEncoding: params.inputEncoding,
      key: edkInfo.plainText,
      iv: IV });

  hmac = createHMAC(
    { hmacAlgorithm: 'SHA256',
      hmacKey: edkInfo.plainText, // should use another key but ok if use the same for now
      cipherText: cipherText,
      iv: IV,
      edk: edkInfo.cipherText,
      edkContext: edkInfo.context,
    });

  return createStorageFormat(
    { cipherText: cipherText,
      iv: IV,
      edk: edkInfo.cipherText,
      edkContext: edkInfo.context,
      hmac: hmac
    }
  );
}

function compareHMACcode(hmac1, hmac2) {
  var sentinel;

  if (hmac1.length !== hmac2.length) {
      return false;
  }

  for (var i = 0; i <= (hmac1.length - 1); i++) {
    sentinel |= hmac1.charCodeAt(i) ^ hmac2.charCodeAt(i);
  }

  return sentinel === 0;
};

//
// DECRYPT
function reverseStorageCheckHMACDecrypt(params) {

  assert(params.sfmt, util.format('no params.sfmt:%j', params));
  assert(params.key, util.format('no params.key:%j', params));

  var unpacked = reverseStorageFormat(params.sfmt),
      hmac,
      decipher;

  hmac = createHMAC(
    { hmacAlgorithm: 'SHA256',
      hmacKey: params.key,
      cipherText: unpacked.cipherText,
      iv: unpacked.iv,
      edk: unpacked.edk, // encrypted
      edkContext: unpacked.edkContext
    });

  // check that not been tampered
  if (!compareHMACcode(hmac.digest(ENCODING), unpacked.hmacCode)) {
    console.log('Encrypted Blob has been tampered with...');
    return null;
  } else {
    console.log('HMACs MATCHED');
  }

  return decrypt({
    cipherText: unpacked.cipherText,
    inputEncoding: params.inputEncoding,
    outputEncoding: params.outputEncoding,
    key: params.key,
    iv: unpacked.iv
  });
}

//
// locally decrypt data returning a buffer with ciphertext
// params.cipherText - Buffer to encrypt
// params.inputEncoding - optional input encoding for text - as use storage format expect base64
// params.outputEncoding - optional output encoding
// params.key - the key to use
// params.iv - the initalization vector to use
//
function decrypt(params) {
  var decipher, deciphered, t;
  assert(params.cipherText, util.format('no params.plain:%j', params));
  assert(params.key, util.format('no params.key:%j', params));
  assert(params.iv, util.format('no params.iv:%j', params));

  decipher = crypto.createDecipheriv(ALGORITHM, params.key, params.iv);
  deciphered = [decipher.update(params.cipherText)];
  deciphered.push(decipher.final());
  deciphered = Buffer.concat(deciphered);
  return deciphered;
}

/*listKeys(function() {
  genDataKey(function() {
    encryptData();
  });
});*/

/*var ciphers = crypto.getCiphers();
console.log(ciphers);

var hashes = crypto.getHashes();
console.log(hashes);*/

// test call generate key and test can decrypt
/*AWSgenAES256DataKey(function(err, keyInfo) {
  console.log('Encrypted key:%j', keyInfo.CiphertextBlob);
  console.log('Decrypt key');
  AWSDecrypt(keyInfo, function(err, data) {
    console.log('end:%j', data);
  });
});*/

//http://www.levigross.com/2014/03/30/how-to-write-an-encrypt-and-decrypt-api-for-data-at-rest-in-nodejs/

/*KEY = crypto.randomBytes(32); // need 256 bit key for AES-256
//console.log(KEY);*/

AWSgenAES256DataKey(function(err, keyInfo) {
  //encryptDecryptBob(keyInfo);
  encryptDecryptFile(keyInfo);
});


function encryptDecryptFile(keyInfo) {
  var sfmt, edkInfo, params,
      cipherBlob, AWSparams,
      unpacked;

  params = {};
  // setup the data to encrypt
  params.plain = privateKey;

  // setup the key information
  edkInfo = {};
  edkInfo.plainText = keyInfo.Plaintext;
  edkInfo.cipherText = keyInfo.CiphertextBlob;
  edkInfo.context = EDK_CONTEXT;

  // encrypt, add hmac, and produce storage format
  sfmt = encryptHMACConvert2StorageFormat(params, edkInfo),
  console.log('LOCALLY Encrypted Storage Format:%j', sfmt);

  // unpack storage format
  unpacked = reverseStorageFormat(sfmt);
  console.log('LOCALLY Encrypted UNPACKED Storage Format:%j', unpacked);

  // setup params needed to decrypt the key
  AWSparams = {};
  AWSparams.CiphertextBlob = unpacked.edk;
  AWSparams.EncryptionContext = unpacked.edkContext;
  AWSdecryptKey(AWSparams, function(err, data) {
    // now have decrypted key unpack the storage format, check hmac code with key, and decrypt data with key
    var pt, params, canon;

    params = {};
    params.sfmt = sfmt;
    params.key = data.Plaintext;
    pt =  reverseStorageCheckHMACDecrypt(params);
    pt = pt.toString('utf-8');
    canon = privateKey.toString('utf-8');
    console.log('1 - storageFMT:%s and plainText:%s', sfmt, pt);
    assert(pt === canon, util.format('plain text:%s is not same as canon:%s', pt, canon));
  });
}



function encryptDecryptBob(keyInfo) {
  var sfmt, edkInfo, params,
      cipherBlob, AWSparams,
      unpacked;
  params = {};
  params.plain = new Buffer('bob');
  params.inputEncoding = null;
  edkInfo = {};
  edkInfo.plainText = keyInfo.Plaintext;
  edkInfo.cipherText = keyInfo.CiphertextBlob;
  edkInfo.context = EDK_CONTEXT;
  sfmt = encryptHMACConvert2StorageFormat(params, edkInfo),
  console.log('LOCALLY Encrypted Storage Format:%j', sfmt);

  unpacked = reverseStorageFormat(sfmt);
  console.log('LOCALLY Encrypted UNPACKED Storage Format:%j', unpacked);
  AWSparams = {};
  AWSparams.CiphertextBlob = unpacked.edk; //new Buffer(awsEncryptedKey, ENCODING);
  AWSparams.EncryptionContext = unpacked.edkContext;

  // Assume plain text key has been thrown away but still have encrypted key - decrypt it with AWS and use to de-crypt data locally
  AWSdecryptKey(AWSparams, function(err, data) {
    var pt, params;

    params = {};
    params.sfmt = sfmt;
    params.key = data.Plaintext;
    params.inputEncoding = ENCODING;
    params.outputEncoding = 'utf-8';
    pt =  reverseStorageCheckHMACDecrypt(params);
    pt = pt.toString('utf-8');
    console.log('1 - storageFMT:%s and plainText:%s', sfmt, pt);
    assert((pt === 'bob'), util.format('plain text:%s: is not bob', pt));
  });
}
