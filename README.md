# node-sodium


Port of the [lib sodium](https://github.com/jedisct1/libsodium) Encryption Library to Node.js.

This a work in progress but most of Lib Sodium as been ported already. Missing are the `afternm` and `beforenm` functions.

There's a "low level" native module that gives you access directly to Lib Sodium, and a friendlier high level API that makes the use of the library a bit easier.

# Usage

Just a quick example that uses the same public/secret key pair to encrypt and then decrypt the message.

    var sodium = require('sodium');        
    var box = new sodium.Box();     // random key pair, and nonce generated automatically
    
    var cipherText = box.encrypt("This is a secret message", "utf8");
    var plainText = box.decrypt(cipherText);
    
    
# Low Level API
A low level API is provided for advanced users. The functions available through the low level API have the exact same names as in lib sodium, and are available via the `sodium.api` object. Here is one example of how to use some of the low level API functions to encrypt/decrypt a message:

    var sodium = require('sodium').api;
    
    // Generate keys
    var sender = sodium.crypto_box_keypair();
    var receiver = sodium.crypto_box_keypair();
    
	// Generate random nonce
    var nonce = new Buffer(sodium.crypto_box_NONCEBYTES);
	sodium.randombytes_buf(nonce);
    
    // Encrypt
    var plainText = new Buffer('this is a message');
    var cipherMsg = sodium.crypto_box(plainText, nonce, receiver.publicKey, sender.secretKey);

    // Decrypt
    var plainBuffer = sodium.crypto_box_open(cipherMsg,nonce,sender.publicKey, receiver.secretKey);

    // We should get the same plainText!
    // We should get the same plainText!
    if( plainBuffer.toString() == plainText) {
        console.log("Message decrypted correctly");
    }
    
As you can see the high level API implementation is easier to use, but the low level API will fill just right for those with experience with the C version of lib sodium. It also allows you to bypass any bugs in the high level APIs.

You can find this code sample in `examples\low-level-api.js`.
    
# Documentation
Please read the work in progress documentation found under `docs/`.

# Lib Sodium Documentation
Lib Sodium is somewhat documented [here](http://mob5.host.cs.st-andrews.ac.uk/html/). Node-Sodium follows the same structure and I will keep documenting it as fast as possible. 

# Install

Tested on Mac and Linux

    npm install sodium
    
node-sodium depends on lib sodium, so if lib sodium does not compile on your platform chances are `npm install sodium` will fail.

# Manual Install
Clone the git repository, and change to the local directory where you ran git clone to, 

    make sodium
    npm install

This compiles Lib Sodium it self, by doing

    cd libsodium
    ./autogen
    ./configure
    make

followed by

    cd ..
    npm build .
    npm install
    

# Code Samples
Please check the fully documented code samples in `test/test_sodium.js`.

# Unit Tests
You need to have mocha test suite installs then you can run the node-sodium unit tests by

    make test
    
# Coverage Reports
	
	make test-cov
	

