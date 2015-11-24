# Overview

Had a requirement to deliver sensitive configuration information to HTTP Restful Services running as Docker Containers on a CoreOS cluster hosted in an AWS VPC.

The high level approach is to encrypt the configuration data, deliver the encrypted version to the Service at startup, and at runtime the Service would decrypt it. Hence the plain text only exists inside the Service memory.

The following implementation approach is taken:
* The data is encrypted using AES-256-CB, the keys are generated and protected using AWS Key Management Service (KMS), and the AES-256-CB implementation is provided by the NodeJS crypto package.
* To protect from tampering a SHA256 HMAC code is generated across the encrypted data, the initilization vector, the encrypted key, and the key context.
* The encoded format contains enough information to allow a party who can access the key in KMS to decrypt to the plain text. It consists of the encrypted_data.iv.encrypted_key.key_context.hmac_code - all parts as base64 encoded.

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
