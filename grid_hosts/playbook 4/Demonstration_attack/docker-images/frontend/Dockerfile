FROM nginx:1.20

# Install required packages
RUN apt-get update && apt-get install -y net-tools iproute2 iputils-ping curl python3 python3-pip
RUN pip3 install Flask 
RUN pip3 install flask-cors

# Copy files to Nginx HTML directory
COPY web/index.html /usr/share/nginx/html
COPY web/app.js /usr/share/nginx/html
COPY ./send_logs_to_asset_monitoring.py /

EXPOSE 9002