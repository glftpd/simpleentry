Installation:

You'll need: g++ openssl + dev files

Compiling the socket lib:

- change to SslSocket directory
- run make
- output is written to ../bin

Installation of socket lib:

- copy libSslSocket.a/so to /usr/lib (only as root - can be done with "make install", too)

 _ O R _ (no root rights required)

- call "export LD_LIBRARY_PATH=/your/path/to/sslsocketbin:$LD_LIBRARY_PATH" (you should add this to your .bash_profile or .bashrc)

Compiling blowcrypt:

- change to blowcrypt directory
- run make
- or run make static
- output is written to ../bin

Compiling entry:

- change to entry directory
- run make
- or run make static
- output is written to ../bin

Setting up entry:

- copy entry.conf.dist from entry directory to ../bin/entry.conf
- edit entry.conf to fit your needs
- if you want to crypt your config use blowcrypt -e entry.conf to do so
- start entry with entry entry.conf or entry -u entry.conf for uncrypted conf

Compiling simplesocks:

- change to simplesocks directory
- run make
- or run make static
- output is written to ../bin

Setting up simplesocks:

- copy simplesocks.conf.dist from simplesocks directory to ../bin/simplesocks.conf
- edit simplesocks.conf to fit your needs
- if you want to crypt your config use blowcrypt -e entry.conf to do so
- start simplesocks with simplesocks simpelsocks.conf or simplesocks -u simplesocks.conf for uncrypted conf

Compiling tbnc:

- change to tbnc directory
- run make
- or run make static
- output is written to ../bin

Setting up tbnc:

- copy tbnc.conf.dist from entry directory to ../bin/tbnc.conf
- edit tbnc.conf to fit your needs
- if you want to crypt your config use blowcrypt -e tbnc.conf to do so
- start tbnc with tbnc tbnc.conf or tbnc -u tbnc.conf for uncrypted conf
