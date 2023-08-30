FROM mysql:debian 
RUN apt-get update; exit 0 
RUN apt-get install -y net-tools iproute2 iputils-ping python3 python3-pip
COPY ./send_logs_to_asset_monitoring.py /

