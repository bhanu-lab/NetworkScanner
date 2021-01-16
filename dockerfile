FROM ubuntu
LABEL  maintainer="bhanu"

EXPOSE 5000
RUN apt-get update
RUN apk update
RUN apt-get install -y python3
RUN apt-get install -y python3-pip
RUN pip3 install flask
COPY . /opt/
ENV FLASK_APP=/opt/main.py
RUN cd /opt/ && pip3 install -r requirements.txt
RUN python3 -m flask run host=127.0.0.1






