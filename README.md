# crypto-utils
 Utilities to help encrypt/decrypt information using node crypt and AWS KMS

 # Key Design Goals for the key management infrastructure
 * The keys are stored in AWS KMS
 * The keys are used by
   ** Services running in Docker Containers in AWS.
   ** Services running in Docker Containers on developers laptops
   ** DevOps utilities running in AWS or developers laptops to encrypt/decrypt data
 * The keys are protected by the AWS KMS
