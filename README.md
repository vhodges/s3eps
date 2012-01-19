
## S3 Encrypting Proxy Server

s3eps acts as a http proxy between end users and AWS s3, encrypting uploaded
files and decrypting the files when they are downloaded.  It's implemented in
Node.

It started out as a summer startup project between an associate and myself.
Unfortunately we finished just before Amazon announced support for server side
encryption, essentially removing our market out from under us.

I still think there's a need for client side encryption where total control
over keys and files can be maintained (Amazon's client side solution requires Java).
Hence I am open sourcing the software as-is.

It is released under the terms of the 3-Clause BSD license.

It was developed and tested under Node version 0.4.10

## Dependencies

there are only a few external libraries used.  To install:

* npm install redis
* npm install hiredis
* npm install rbytes




