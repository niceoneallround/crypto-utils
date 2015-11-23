# crypto-utils
A set of utilities that supports
* encryption and decryption of data using nodeJS crypto package and AWS Key Management Services
* provided an encoded format of the encrypted information that has the following properties
  * Contains enough information so that the data can be decrypted by parties who can access the key in AWS.kms
  * Protects against tampering using an HMAC

## The design goals for key management are
* The keys are stored in AWS KMS
* The keys are used to generate data keys that are used to encrypt/decrypt information by
  * NodeJS applications running in Docker Containers, either in AWS or developers laptops
  * DevOps utilities running in AWS or developers laptops
* The keys are protected by the AWS KMS polices

## The package provides the following utilities
* cryptoUtils.js provides
  * encryptHMACEncode
  * decodeHMACDecrypt
* awsKMSUtils.js
  * create - create a KMS connection
  * generateDataKey
  * decryptDataKey
* nodeCryptoUtils.js
  * encrypt
  * decrypt
  * createHMAC
  * compareHMACcode
* formatUtils.js
 * encode
 * decode
