FROM openjdk:17-jdk-slim
ARG JAR_FILE=target/synthlab-api-0.0.1-SNAPSHOT.jar
COPY ${JAR_FILE} synthlab-api.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "synthlab-api.jar"]