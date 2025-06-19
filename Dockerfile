FROM amazoncorretto:21.0.7-al2023

ARG JAR_FILE=build/libs/*.jar

RUN dnf install -y shadow-utils && \
    useradd --create-home --shell /bin/bash appuser && \
    dnf clean all

COPY ${JAR_FILE} app.jar

RUN chown appuser:appuser app.jar

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java","-jar","/app.jar"]
