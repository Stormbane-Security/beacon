FROM maven:3.8-openjdk-11 AS build
WORKDIR /app
COPY pom.xml .
COPY src/ src/
RUN mvn package -q -DskipTests

FROM openjdk:11-jre-slim
COPY --from=build /app/target/log4shell-app.jar /app.jar
EXPOSE 8080
CMD ["java", "-jar", "/app.jar"]
