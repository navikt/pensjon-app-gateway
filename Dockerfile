FROM gcr.io/distroless/java21-debian12:nonroot

ENV TZ="Europe/Oslo"

COPY target/pensjon-app-gateway-*.jar app.jar
WORKDIR /app

CMD ["app.jar"]
