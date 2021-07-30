# DNS over QUIC container

Alex Mayrhofer <alexander.mayrhofer@nic.at>, July 2021

This Dockerfile builds (and starts) a simple DNS over QUIC (DoQ) proxy - as a "proof of concept" level container, based on the DoQ proxy `quicdoq` (https://github.com/private-octopus/quicdoq). 

When run, the container will start `quicdoq` in server mode, listening on port 784/udp (by default). The container will forward received DNS queries to 8.8.8.8 by default (see configuration below).

## Building the container

```
docker build .
```

## Running the container

```
docker run -d --name quicdoq_server -p 784:784/udp <image id>
```

## Configuration

The default port (784) and default forwarding destination (8.8.8.8) can be changed using environment variables as follows:

  * **DOQ_PORT**: Sets the UDP port number that quicdoq_app will listen on, defaults to 784
  * **DOQ_DESTINATION**: Sets the IP address of the upstream nameserver to be used. Defaults to 8.8.8.8

Configuration can be performed from the `docker run` command as follows:

```
docker run -d --name quicdoq_server -p 8853:8853/udp --env DOQ_PORT=8853 --env DOQ_DESTINATION=1.1.1.1 <image id>
```

(Alternatively, a `docker-compose` file can be used, of course)

## Sending a query 

To send a query, `quicdoq_app` can be used from within the container as well. In order to do this, open a shell into the same container, and use the binary in client mode from within the container as follows:

```
docker exec -it <container id> /bin/bash
./quicdoq_app localhost 784 www.nic.at:AAAA
```

## Open issues

  * clean up build environment in image
  * `quicdoq` itself is probably not using the latest -03 version of the protocol (which added a 2-byte header). This doesn't matter if the only client is quicdoq itself, but obviously hinders interopability ;)


