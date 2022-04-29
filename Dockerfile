FROM ubuntu:latest

ADD ./main /main

RUN mkdir /config
RUN mkdir /certs

EXPOSE 443

CMD /main
