# quicdoq

Quicdoq is a simple implementation of DNS over Quic, as specified in
[draft-ietf-quic-dnsoquic](https://datatracker.ietf.org/doc/draft-ietf-quic-dnsoquic/).
It is written in C, based on [Picoquic](https://github.com/private-octopus/picoquic).
Like Picoquic itself, it has a dependency
on the [Picotls implementation of TLS 1.3](https://github.com/h2o/picotls),
and on the Crytographic Libraries of OpenSSL.
The current code supports the version 03 of the draft, with ALPN "doq-i03".

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

Alternatively, the directory `docker` contains a Dockerfile to build a container for quicdoq - See [Docker README](docker/README.md) for instructions.

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

# Running the demo application

This distribution includes a demo application, which is meant to illustrate the usage of
the API. 

```
    +------------+      +-------------------+
    | Client CLI |      | Relay server      |
    +------------+      +---------+---------+      +-----------+
    | Quicdoq    |      | Quicdoq | Stub    |      | Recursive |
    +------------+      +---------+ DNS     |      | DNS 
    | Quic       |      | Quic    | resolver|      | Resolver  |
    +------------+      +---------+---------+      +-----------+     
    | UDP        |<---->| UDP     | UDP     |<---->| UDP       |
    +------------+      +---------+---------+      +-----------+ 
```
The demo client has a simple command line interface:
```
quicdoq_app <options> [server_name [port [scenario]]]
```
The scenario consists of a set of dns queries, e.g.:
```
www.example:A www.example.example:AAAA example.net:NS
```
The client will set up a DNS over QUIC connection to the specified server,
send the queries, wait for responses and display these responses.

The server receives the DNS queries from the DNS over QUIC stack, and passes
them to a "relay server" which simply forwards them to a designated
recursive resolver. The responses will be relayed back to the client
using DNS over QUIC.

The server also has a simple command line interface:
```
quicdoq_app <options> -p port -d dns-server
```
The DNS server is designated by its IP address, such as `8.8.8.8`.
The options for client and server can be displayed with the command
```
quicdoq_app -h
```


