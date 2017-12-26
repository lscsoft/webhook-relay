FROM python:3.6-alpine3.6
ADD . /code
WORKDIR /code 
RUN pip install -r requirements.txt

CMD ["rq", "worker", "--config", "settings"]
