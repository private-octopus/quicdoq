FROM debian:buster-slim
ENV DOQ_PORT=784 DOQ_DESTINATION=8.8.8.8
RUN apt-get update && apt-get install cmake git ca-certificates libssl-dev build-essential pkg-config --no-install-recommends -y
# dependencies - picotls
RUN git clone https://github.com/h2o/picotls /var/tmp/picotls
WORKDIR /var/tmp/picotls
RUN git submodule init && git submodule update
RUN cmake . && make 
# dependencies - picoquic
RUN git clone https://github.com/private-octopus/picoquic /var/tmp/picoquic
WORKDIR /var/tmp/picoquic
RUN cmake . && make
# quicdoq itself
RUN git clone https://github.com/private-octopus/quicdoq /var/tmp/quicdoq
WORKDIR /var/tmp/quicdoq
RUN cmake . && make
RUN cp quicdoq_app /bin && mkdir /etc/picoquic && cp ../picoquic/certs/cert.pem /etc/picoquic/cert.pem && cp ../picoquic/certs/key.pem /etc/picoquic/key.pem
RUN cd /var/tmp && rm -rf quicdoq picoquic picotls
RUN dpkg --purge build-essential pkg-config libssl-dev cmake
RUN apt-get -y autoremove && apt-get clean && rm -f /var/lib/apt/lists/*_*
WORKDIR /bin
EXPOSE ${DOQ_PORT}/udp
CMD ./quicdoq_app -c /etc/picoquic/cert.pem -k /etc/picoquic/key.pem -p ${DOQ_PORT} -d ${DOQ_DESTINATION}
