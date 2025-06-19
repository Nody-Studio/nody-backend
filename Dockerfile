FROM eclipse-temurin:21.0.7_6-jdk-ubi9-minimal

ARG JAR_FILE=build/libs/*.jar

RUN useradd --create-home --shell /bin/bash appuser

COPY ${JAR_FILE} app.jar

RUN chown appuser:appuser app.jar

USER appuser

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java","-jar","/app.jar"]