/*
 * S3 Encrypting Proxy Server
 * (c) 2011 Sourdough Labs Research and Development Corp and Ed Levinson, All Rights Reserved.
 *
 * See LICENSE for terms.
 *
 * Act as a http proxy between end users and AWS s3, encrypting uploaded files and decrypting
 * the files when they are downloaded.
 */

var http = require('http');
var sys  = require('sys');
var crypto  = require('crypto');
var redis = require("redis");
var rbytes = require('rbytes');
var fs = require('fs');

/* Set to true to display instrumentation */
var debug = false;

var redisclient = redis.createClient();

redisclient.on("error", function (err) {
    console.log("Redis Error: " + err);
});

/* Generate a secure randome string to use as our encryption key*/
function generateCryptoKey() {
    rbuff = rbytes.randomBytes(16);
    return rbuff.toHex().toString();
}

/* Synchronously make a set of directories */
function mkdirp(path) {
    var pathSegments= path.split("/");

    if( pathSegments[0] == '' ) {
        pathSegments= pathSegments.slice(1);
    }

    for(var i=0; i<=pathSegments.length; i++) {
        var pathSegment= "./"+pathSegments.slice(0,i).join("/");
        try {
            fs.statSync(pathSegment);
        }
        catch(e) {
            fs.mkdirSync(pathSegment, 0755);
        }
    }
}

/* Generate a sha1 of the request url. this is our 'db' key
 *
 * This is used as the hash key for our db (why give attackers a clue
 * as to what/where the crypto key is for?!)
 *
 */
function shaURI(uri) {
    shasum = crypto.createHash('sha1');
    shasum.update(uri);
    return shasum.digest('hex');
}

function saveRecord(urisha, access_key, data) {
    record = JSON.stringify(data);

    first = urisha.slice(0, 3);
    second = urisha.slice(3, 6);

    path = 'db/' + access_key + '/' + first + "/" + second;

    mkdirp(path); // Make the directories to hold the record, if needed.

    fs.writeFile(path + "/" + urisha, record, function (err) {
        if (err) {
            console.log('FileIO Error:' + err);
        }
    });
}


/* Record stats for Accounting/billing purposes */
function dl_stats(accesskey, dlin, dlout) {
    redisclient.multi()
        .hincrby(accesskey, "download:in", dlin)
        .hincrby(accesskey, "download:out", dlout)
        .hincrby(accesskey, "download:count", 1)
        .exec(function (err, results) {
            if (err) {
                console.log("Redis DL Stats Error: " + err);
            }
        });
}

function ul_stats(accesskey, ulin, ulout) {
    redisclient.multi()
        .hincrby(accesskey, "upload:in", ulin)
        .hincrby(accesskey, "upload:out", ulout)
        .hincrby(accesskey, "upload:count", 1)
        .exec(function (err, results) {
            if (err) {
                console.log("Redis UL Stats Error: " + err);
            }
        });
}

function proxyRequest(request, response, cipher, decipher, contentlength, access_key, urisha) {

    // We only proxy to s3, in future we'll need to allow for different end points
    var proxy = http.createClient(80, "s3.amazonaws.com" /*request.headers['host']*/);
    var proxy_request = proxy.request(request.method, request.url, request.headers);

    proxy_request.addListener('response', function (proxy_response) {

        var dlin = 0;
        var dlout = 0;

        /*
         *  Read from s3, write to client
         */
        proxy_response.addListener('data', function(chunk) {

            dlin += chunk.length;
            if (decipher) {
                chunk = decipher.update(chunk,'binary','binary');
                dlout += chunk.length;
            }

            response.write(chunk, 'binary');
        });

        proxy_response.addListener('end', function() {

            if (decipher) {
                chunk = decipher.final('binary');
                dlout += chunk.length;
                response.write(chunk, 'binary');

                sys.log(request.connection.remoteAddress + ": " +access_key + " " + urisha + " - DL in = " + dlin + ", out = " + dlout);
                dl_stats(access_key, dlin, ((dlout === 0) ? dlin : dlout));
            }

            response.end();
        });

        if (decipher) {
            // Send back the original unencrypted content-length if we're decrypting
            proxy_response.headers['content-length'] = contentlength;
        }

        response.writeHead(proxy_response.statusCode, proxy_response.headers);
    });

    var ulin = 0;
    var ulout = 0;

    /*
     * Read from client, Write to s3
     */
    request.addListener('data', function(chunk) {
        ulin += chunk.length;
        if (cipher) {
            chunk = cipher.update(chunk,'binary','binary');
            ulout += chunk.length;
        }
        proxy_request.write(chunk, 'binary');
    });

    request.addListener('end', function() {
        if (cipher) {
            chunk = cipher.final('binary');
            ulout+= chunk.length;
            proxy_request.write(chunk, 'binary');

            sys.log(request.connection.remoteAddress + ": " +access_key + " " + urisha + " - UL in = " + ulin + ", out = " + ulout);

            ul_stats(access_key, ulin, ((ulout === 0) ? ulin : ulout));
        }
        proxy_request.end();
    });

}

function deny(response, msg) {
  response.writeHead(403);
  response.write(msg);
  response.end();
}

var cipher_urls = /^\/.*\/.*/g; // Match /bucket/filename pattern, so we only encrypt/decrypt those
cipher_urls.compile();

sys.log("S3 Encrypting Proxy Server Version 1.0 - Started");

http.createServer(function(request, response) {

    var urisha = shaURI(request.url);
    var cipher = null;
    var decipher = null;

    // This will break if they ever change the format of this field!
    // Used to identify our clients/users
    var access_key = request.headers['authorization'].split(":")[0].split(" ")[1];

    // Determine whether to encrypt, decrypt or do nothing
    if (request.method == "GET" && cipher_urls.test(request.url)) {
        /* Download from S3 to client. */
        sys.log(request.connection.remoteAddress + ": " +access_key +  " "  + urisha + " - 'DECRYPT' " );

        first = urisha.slice(0, 3);
        second = urisha.slice(3, 6);
        path = 'db/' + access_key + '/' + first + "/" + second;

        // I'm a little concerned this in synchronous, but it breaks and I don't know why :(
        data = fs.readFileSync(path + "/" + urisha);
        record = JSON.parse(data);
        key = record.cryptokey;
        contentlength = record.contentlength;

        decipher = crypto.createDecipher('aes-256-cbc', key);
        proxyRequest(request, response, null, decipher, contentlength, access_key, urisha);
    } else if (request.method == "PUT"  && cipher_urls.test(request.url)) {
        /* Upload from client to S3 */
        sys.log(request.connection.remoteAddress + ": " +access_key +  " "  + urisha + " - 'ENCRYPT' " );

        // Get the integer value for content-length
        contentlength = parseInt( request.headers['content-length'], 10 );
        key = generateCryptoKey();

        record = {
            "cryptokey": key,
            "contentlength":contentlength
        };

        saveRecord(urisha, access_key, record);

        // Adjust the content-length upto the next multiple of 16 (which will happen as a result of the
        // encryption process).
        contentlength = parseInt( ((contentlength + 16 ) / 16), 10) * 16;
        request.headers['content-length'] = contentlength;

        cipher = crypto.createCipher('aes-256-cbc', key);
        proxyRequest(request, response, cipher, null, null, access_key, urisha);
    }
    else {
        /* Fall through to basic web proxy, with no crypto */
        sys.log(request.connection.remoteAddress + ": " +access_key +  " "  + urisha + " - 'PROXY' " );

        proxyRequest(request, response, null, null, null, access_key, urisha);
    }

}).listen(8080);
