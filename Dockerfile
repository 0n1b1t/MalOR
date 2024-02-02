FROM ubuntu:22.04
RUN apt-get update && \
    apt-get install -y curl vim git apache2 libapache2-mod-uwsgi libapache2-mod-wsgi-py3 apache2-utils ssl-cert software-properties-common libyara-dev python3-pip python3-gridfs && \
    apt-get clean
RUN a2enmod wsgi
RUN a2enmod ssl
RUN ln -s /usr/bin/python3 /usr/bin/python
RUN mkdir /opt/malor
RUN mkdir -p /nfs/primary/
WORKDIR /opt/malor
COPY requirements.txt entrypoint.py config /opt/malor/
RUN pip install -r requirements.txt
RUN ln -s /usr/local/lib/python3.10/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so
CMD python /opt/malor/entrypoint.py