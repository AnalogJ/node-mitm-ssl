var https = require('https')
    , http  = require('http')
    , path  = require('path')
    , fs    = require('fs')
    , net   = require('net')
    , sys   = require('sys')
    , url   = require('url')
    , clrs  = require('colors')
    , EE    = require('events').EventEmitter
    , crypto = require('crypto')
    , cp = require('child_process')


/* *********************************************************************************************************************
 * Utility Functions
 * ********************************************************************************************************************/
var process_options = function(proxy_options) {
    var options = proxy_options || {}

    if(!options.virtual_server_http_port)       options.virtual_server_http_port            = 80;
    if(!options.virtual_server_https_port)      options.virtual_server_https_port           = 443;
    if(!options.verbose === false)              options.verbose                             = true;
    return options;
}

var process_url = function(request, type) {
    var req_url = url.parse(request.url, true);
    if(!req_url.protocol) req_url.protocol = type + ":";
    if(!req_url.hostname) req_url.hostname = request.headers.host;

    return req_url;
}




// move into a seperate module of some sort.
var creds = {};

//This method only works on node 0.11.7+ , because stupid syncr methods are stupid
function getCredentialsContext (hostname /*eg. www.github.com*/, cb) {
    sys.log("attempting to find credentials for:" + hostname)
    //check if credentials already exist
    hostname_cred = creds[hostname]

    if (hostname_cred){
        sys.log('found creds already existing')
        cb(null, crypto.createCredentials({
            key: fs.readFileSync(hostname_cred.key),
            cert: fs.readFileSync(hostname_cred.cert),
            ca: fs.readFileSync('ca.crt')
        }).context)
    }
    else{
        genCredentials(hostname, cb)
    }

}

function genCredentials(hostname,cb){
    //this call is to check for certificats that currently exist ont he file system but are not loaded in the creds obj.
    //this may be redundant and should be moved into some sort of init function

    if(fs.existsSync(hostname+'.key') && fs.existsSync(hostname+'.crt')){
        //keys already exist.
        sys.log('found creds on file system')
        var hostname_cred = {
            'key' : hostname +'.key',
            'cert' : hostname + '.crt'
        }
        creds[hostname] = hostname_cred;
        cb(null, crypto.createCredentials({
            key: fs.readFileSync(hostname_cred.key),
            cert: fs.readFileSync(hostname_cred.cert),
            ca: fs.readFileSync('ca.crt')
        }).context);
    }
    else{
        //keys dont exist, create them using openssl
        sys.log('generating creds')
        var key = hostname+'.key';
        var csr = hostname+'.csr';
        var crt = hostname+'.crt';
        var timestamp = new Date().getTime();
        // gen private
        cp.exec('openssl genrsa -out '+key+' 4096 ', function(err, priv, stderr) {
            // gen csr
            cp.exec('openssl req -new -key '+key+' -out '+csr+' -subj "/C=US/ST=CA/L=SF/O=Bandit/OU=Proxy/CN='+hostname+'"', function(err, pub, stderr) {
                cp.exec('openssl x509 -req -days 365 -in '+csr+' -CA ca.crt -CAkey ca.key -set_serial '+timestamp+' -out '+crt, function(err, priv, stderr) {
                    //sign csr and gen crt
                    sys.log('finished generating creds')
                    cb(null, crypto.createCredentials({
                        key: fs.readFileSync(key),
                        cert: fs.readFileSync(crt),
                        ca: fs.readFileSync('ca.crt')
                    }).context);
                })

            });

        });

    }

}

/* *********************************************************************************************************************
 * Simple Request Handler
 * ********************************************************************************************************************/

function handle_request(that, virtual_server_request, virtual_server_response, type){
    var processor = that.processor_class ? new that.processor_class.processor() : null;
    var req_url   = process_url(virtual_server_request, type, processor);
    var hostname  = req_url.hostname;
    var pathname  = req_url.pathname + ( req_url.search || "");

    if(processor) processor.emit('request', virtual_server_request, req_url);

    if(that.options.verbose) console.log(type.blue + " proxying to " +  url.format(req_url).green);

    // Generate virtual_client_request
    var request_options = {
        host: hostname
        , port: req_url.port || (type == "http" ? 80 : 443)
        , path: pathname
        , headers: virtual_server_request.headers
        , method: virtual_server_request.method
    }

    var virtual_client = (req_url.protocol == "https:" ? https : http).request(request_options, function(server_response) {
        if(processor) processor.emit("response", server_response);

        server_response.on("data", function(d) {
            virtual_server_response.write(d);
            if(processor) processor.emit("response_data", d);
        });

        server_response.on("end", function() {
            virtual_server_response.end();
            if(processor) processor.emit("response_end");
        })

        server_response.on('close', function() {
            if(processor) processor.emit("response_close");
            server_response.connection.end();
        })

        server_response.on("error", function(err) {})
        virtual_server_response.writeHead(server_response.statusCode, server_response.headers);
    })

    virtual_client.on('error', function(err) {
        virtual_server_response.end();
    })

    virtual_server_request.on('data', function(d) {
        virtual_client.write(d, 'binary');
        if(processor) processor.emit("request_data", d);
    });

    virtual_server_request.on('end', function() {
        virtual_client.end();
        if(processor) processor.emit("request_end");
    });

    virtual_server_request.on('close', function() {
        if(processor) processor.emit("request_close");
        virtual_client.connection.end();
    })

    virtual_server_request.on('error', function(exception) {
        virtual_server_response.end();
    });

}






/* Nomenclature
  * virtual_server : this is the virtual server that the client is connecting to. This is the client facing portion of the proxy server
  * virtual_client : this is the virtual client that forwards requests on behalf of the actual client.
  * virtual_server_http_port : this is the public port for the proxy server, provide this to your devices
  * virtual_server_https_port : this is a private port for https connections, it will be used automatically when needed.
  *
  * */


/* *********************************************************************************************************************
 * Main Function
 * ********************************************************************************************************************/
function Proxy(proxy_options) {
    this.options = process_options(proxy_options);
    //this.processor_class = processor_class ? new Processor(processor_class) : null;

    var that = this;

    var https_opts = {
        key:    fs.readFileSync('www.github.com.key'),
        cert:   fs.readFileSync('www.github.com.crt'),
        ca: fs.readFileSync('ca.crt'),
        SNICallback: getCredentialsContext
    };


    // HTTPS Virtual Server.

    var virtual_server_https = https.createServer(https_opts, function (request, response) {
        sys.log("http message to be handled.")
        handle_request(that, request, response, "https");
    });

    virtual_server_https.addListener('error', function(err) {
        sys.log("error on virtual_server_https");
        sys.log(err);
    });
    virtual_server_https.listen(this.options.virtual_server_https_port);
    if(this.options.verbose) console.log('https virtual server'.blue + ' started '.green.bold + 'on port '.blue + (""+this.options.virtual_server_https_port).yellow);


    // HTTP Virtual Server
    var virtual_server_http = http.createServer(function(request, response) {
        sys.log("http message to be handled.")
        handle_request(that, request, response, "http");
    });
    virtual_server_http.addListener('error', function(err) {
        sys.log("error on virutal_server_http");
        sys.log(err);
    });

    // Handle connect request (for https), the client is attempting to upgrade to a https connection.
    virtual_server_http.addListener('upgrade', function(req, socket, upgradeHead) {
        sys.log("attempting to upgrade the connection.")
        var proxy = net.createConnection(that.options.virtual_server_https_port, 'localhost');

        proxy.on('connect', function() {
            socket.write( "HTTP/1.0 200 Connection established\r\nProxy-agent: Netscape-Proxy/1.1\r\n\r\n");
        });

        // connect pipes
        proxy.on( 'data', function(d) { socket.write(d)   });
        socket.on('data', function(d) { try { proxy.write(d) } catch(err) {}});

        proxy.on( 'end',  function()  { socket.end();      });
        socket.on('end',  function()  { proxy.end();       });

        proxy.on( 'close',function()  { socket.end();      });
        socket.on('close',function()  { proxy.end();       });

        proxy.on( 'error',function()  { socket.end();      });
        socket.on('error',function()  { proxy.end();       });
    });


    virtual_server_http.listen(this.options.virtual_server_http_port);
    if(this.options.verbose) console.log('http virtual server '.blue + 'started '.green.bold + 'on port '.blue + (""+this.options.virtual_server_http_port).yellow);
}

Proxy({verbose: true});