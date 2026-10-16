FROM europe-north1-docker.pkg.dev/cgr-nav/pull-through/nav.no/jre:openjdk-21@sha256:343fee3b95d33af866ca83fd226be0afc2a8235e7399b12a94ca2fc6ad075655

ENV TZ="Europe/Oslo"

COPY target/pensjon-app-gateway-*.jar /app/app.jar
WORKDIR /app

CMD ["-jar","app.jar"]
