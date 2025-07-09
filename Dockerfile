FROM eclipse-temurin:21-jre

RUN apt-get update && apt-get install -y \
  dumb-init \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV TZ="Europe/Oslo"

COPY java-opts.sh .
RUN chmod +x java-opts.sh

COPY target/pensjon-app-gateway-*.jar app.jar

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["bash", "-c", "source ./java-opts.sh && exec java ${DEFAULT_JVM_OPTS} ${JAVA_OPTS} -jar app.jar ${RUNTIME_OPTS} $@"]
