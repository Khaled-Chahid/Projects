ARG LOCALSTACK_IMAGE=localstack/localstack:4.14.0
FROM ${LOCALSTACK_IMAGE}

COPY init-aws.sh /etc/localstack/init/ready.d/init-aws.sh
RUN chmod +x /etc/localstack/init/ready.d/init-aws.sh
