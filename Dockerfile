FROM eclipse-temurin:17-jdk-jammy

WORKDIR /app

COPY target/api-gateway.jar app.jar

ENTRYPOINT ["java","-jar","/app/app.jar"]
