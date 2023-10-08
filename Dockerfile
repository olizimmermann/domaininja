FROM python:3.10

WORKDIR /domaininja

COPY ./requirements.txt /domaininja/requirements.txt
COPY ./ninja.py /domaininja/ninja.py
COPY ./modules /domaininja/modules
COPY ./sql /domaininja/sql


RUN pip install --no-cache-dir --upgrade -r /domaininja/requirements.txt

# Run as non-root user
RUN useradd -m -u 1000 -U -s /bin/sh -d /domaininja domaininja
# write permission for non-root user
RUN chown -R domaininja:domaininja /domaininja
USER domaininja
CMD ["python3", "/domaininja/ninja.py"]