FROM maven as build

WORKDIR /app

COPY . .

RUN mvn clean install -DskipTests


# IMAGEN MODELO
FROM eclipse-temurin:21-jre

WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

# PUERTO DE EJECUCION DEL CONTENEDOR -> INFORMATIVO
EXPOSE 8080

# CONSTRUIR APLICACION CUANDO EL CONTENEDOR INICIE
ENTRYPOINT ["java", "-jar", "app.jar"]


