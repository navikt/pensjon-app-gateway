FROM europe-north1-docker.pkg.dev/cgr-nav/pull-through/nav.no/jre:openjdk-21@sha256:c33bf41fe071380c651e5ea7831a27086ba48a5a9114330016d2343a1e800e51

ENV TZ="Europe/Oslo"

COPY target/pensjon-app-gateway-*.jar /app/app.jar
WORKDIR /app

CMD ["-jar","app.jar"]
