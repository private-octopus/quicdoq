# quicdoq

Quicdoq is a simple implementation of DNS over Quic, as specified in
[draft-huitema-quic-dnsoquic](https://datatracker.ietf.org/doc/draft-huitema-quic-dnsoquic/).
It is based on [Picoquic](https://github.com/private-octopus/picoquic).
Like Picoquic itself, it has a dependency
on the [Picotls implementation of TLS 1.3](https://github.com/h2o/picotls),
and on the Crytographic Libraries of OpenSSL.

# Building Quicdoq

Quicdoq is developed in C, and can be built under Windows or Linux. Building the
project requires first managing the dependencies, 
[Picoquic](https://github.com/private-octopus/picoquic) and
[Picotls](https://github.com/h2o/picotls)
and OpenSSL. 

## Quicdoq on Windows

To build Picoquic on Windows, you need to:

 * Install and build Openssl on your machine

 * Document the location of the Openssl install in the environment variable OPENSSLDIR
   (OPENSSL64DIR for the x64 builds)

 * Clone and compile Picotls, using the Picotls for Windows options

 * Clone and compile Picoquic, using the Visual Studio 2017 solution picoquic.sln.

 * Clone and compile Quicdoq, using the Visual Studio 2017 solution quicdoq.sln.

 * You can use the unit tests included in the Visual Studio solution to verify the port.

## Quicdoq on Linux

To build Quicdoq on Linux, you need to:

 * Install libssl-dev or build Openssl on your machine

 * Clone and compile Picotls, using cmake as explained in the Picotls documentation.

 * Clone and compile Picotls, using cmake as explained in the Picoquic documentation.

 * Clone and compile Quicdoq:
~~~
   cmake .
   make
~~~
 * Run the test program `quidoq_t` to verify the port.

## Quicdoq on MacOSX

Same build steps as Linux.

## Picoquic on FreeBSD

Same build steps as Linux.