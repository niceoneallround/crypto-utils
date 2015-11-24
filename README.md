# Overview

Had a requirement to deliver sensitive configuration information to HTTP Restful Services running inside Docker Containers on a CoreOS cluster hosted in an AWS VPC.

The high level approach is to encrypt the configuration data, deliver the encrypted data to the Service at startup via the command line, and the Service decrypts it such that he plain text only exists inside the Service's memory.

The following implementation approach is taken:
* The data is encrypted using an AES-256-CB implementation provided by the NodeJS crypto package. 
* The encryption keys are generated and protected using the AWS Key Management Service (KMS) and KMS master keys.
* An encoded format is defined that can be stored or sent over the wire, and has the following properties
 * contains enough information such that if a party can access the key inside KMS it can decrypt to the plain text. This information is: the encrypted data, the initialization vector, the encrypted key, and the key context.
 * protects against tampering by generating a SHA256 HMAC code across the encrypted data, iv, encrypted key, and the key context.
 * is of the following format 'encrypted_data.iv.encrypted_key.key_context.hmac_code'. All parts as base64 encoded

## The design goals for key management are
* Only the keys are stored in AWS KMS, for privacy reasons the data is not.
* KMS master keys are used to generate data keys that are then used to encrypt/decrypt information outside of KMS. For example
  * NodeJS applications running in Docker Containers, either in AWS or developers laptops
  * DevOps utilities running in AWS or developers laptops
* The keys are protected by the AWS KMS polices, along with a usage audit trail provided by AWS cloud trail. The key context captures what resource is being accessed, and what service is accessint it.

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
