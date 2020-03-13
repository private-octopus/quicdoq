# quicdoq

Quicdoq is a simple implementation of DNS over Quic, as specified in
[draft-huitema-quic-dnsoquic](https://datatracker.ietf.org/doc/draft-huitema-quic-dnsoquic/).
It is written in C, based on [Picoquic](https://github.com/private-octopus/picoquic).
Like Picoquic itself, it has a dependency
on the [Picotls implementation of TLS 1.3](https://github.com/h2o/picotls),
and on the Crytographic Libraries of OpenSSL.

# Quicdoq components

The Quicdoq distribution has three main components:

1) A library that implements the DNS over QUIC specification. 
   The library defines a call back API that can be used to implement DoQ client or a DoQ server.

2) A simple UDP backend that exercises the callback API and provides an interface
   between Quicdoq and an UDP based DNS service. 

3) A command line application that can be used either as simple client or to
   instantiate the UDP backed server.

Partners can use the library to enable DNS over QUIC in existing DNS clients or DNS servers.

The sample application can be used to quickly prototype DNS over Quic with an existing
server, using a local UDP connection to submit queries from Quicdoq to the local server.

The sample client implementation is not meant for production use. It is mainly a
demonstration tool. It can be used to quickly enter a few queries, and see the responses
coming back from the selected server.

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