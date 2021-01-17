FROM ubuntu
LABEL  maintainer="bhanu"

EXPOSE 5000
RUN apt-get update
RUN apt-get install -y python3
RUN apt-get install -y python3-pip
RUN pip3 install flask
COPY . /opt/
ENV FLASK_APP=/opt/main.py
RUN cd /opt/ && pip3 install -r requirements.txt
ENTRYPOINT [ "python3" ]
