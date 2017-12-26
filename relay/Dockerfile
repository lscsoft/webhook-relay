FROM python:3.6-alpine3.6
ADD . /code
WORKDIR /code
RUN pip install -r requirements.txt
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "listen:app"]
