FROM ubuntu:16.04

# You may want to change the uhp user id inside the container if
# you're going to mount an external log directory.  The internal uid
# needs write permissions to the external volume.
#
# E.g. to save uhp logs to /var/log/uhp on the host OS, run docker with ...
#
# 	-v /var/log/uhp:/opt/uhp/log
# 
# ... and make sure /var/log/uhp is writable by the uhp uid inside the container.
ARG FOG_UID=903

# Install packages
RUN apt-get update && apt-get install -y git supervisor python3 authbind

# What ports should we listen on, and what templates should we run?
ARG LISTENERS=generic-listener:80

# Create the uhp user
RUN useradd -u ${FOG_UID} -s /bin/false uhp 

# Add our honeypot and a supervisord file to start it
WORKDIR /opt/uhp/
COPY uhp.py /opt/uhp/
COPY hpfeeds.py /opt/uhp/
COPY configs/*.json /opt/uhp/
COPY supervisor-template.conf /opt/uhp/
RUN mkdir -p /opt/uhp/log && \
	chown $FOG_UID /opt/uhp/log && \
	echo '0.0.0.0/0:1,1023' > /etc/authbind/byuid/$FOG_UID && \
	for spec in $LISTENERS; do\
		config=$(echo $spec | cut -f 1 -d :);\
		port=$(echo $spec | cut -f 2 -d :);\
		sed -e "s/PORT/$port/g;s/CONFIG/$config/g" supervisor-template.conf >> /etc/supervisor/conf.d/uhp.conf;\
	done

ENV PATH="/opt/uhp:${PATH}"
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]

# How to build the container:
#
# docker build -t uhp --build-arg "LISTENERS=<config:port> ... [configN:portN]"
# 
# E.g.
# docker build -t uhp --build-arg "LISTENERS=smtp.json:25 http-log-headers.json:80" .
#
# How to run the container:
#
# docker network create --subnet 192.168.2.0/24 honey
# docker run --rm --name uhp --network honey --ip 192.168.2.5 --link broker uhp
#
# To log outside the container:
#
# mkdir /var/log/uhp
# chown 903 /var/log/uhp
# docker run --rm --name uhp --network honey --ip 192.168.2.5 \
#       -v /var/log/uhp:/opt/uhp/log --link broker uhp
#
# To run one instance of the uhp instead of letting supervisor manage
# the daemons:
#
# docker run --rm --name uhp --network honey --ip 192.168.2.5 \
#       -v /var/log/uhp:/opt/uhp/log uhp \
#       uhp.py -f /opt/uhp/log/uhp.json generic-listener.json 8081
#
# Use authbind to bind to ports lower than 1024:
#
# docker run --rm --name uhp --network honey --ip 192.168.2.5 \
#        -v /var/log/uhp:/opt/uhp/log uhp \
#       authbind --deep uhp.py -f /opt/uhp/log/uhp.json \
#       generic-listener.json 80
