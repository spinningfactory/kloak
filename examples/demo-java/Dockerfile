FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /app
COPY DemoApp.java .
RUN javac DemoApp.java

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=builder /app/DemoApp.class .
CMD ["java", "DemoApp"]
