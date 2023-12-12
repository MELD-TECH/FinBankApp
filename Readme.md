# Getting Started

# Overview
This is a simple application to demonstrate authentication and authorization concepts. The application exposes API end-points which is consumed by a React application or any other client. 
- This service uses an in-memory database (H2) to store the data. 
- The end-points (check this class for list of end-points - com.example.controller.UserController) can be accessed on port 8080 (default). To change the port, you can change it on the application-properties.xml file by specifying the new server port.  

# Technologies Used And Reference Guides
* [Official Apache Maven documentation](https://maven.apache.org/guides/index.html)
* [Spring Data JPA](https://docs.spring.io/spring-boot/docs/3.1.6/reference/htmlsingle/index.html#data.sql.jpa-and-spring-data)
* [Spring Security](https://docs.spring.io/spring-boot/docs/3.1.6/reference/htmlsingle/index.html#web.security)
* [Spring Web](https://docs.spring.io/spring-boot/docs/3.1.6/reference/htmlsingle/index.html#web)
* [Spring Boot and OAuth2](https://spring.io/guides/tutorials/spring-boot-oauth2/)
* [Building REST services with Spring](https://spring.io/guides/tutorials/rest/)

# Requirements
For building and running the application you need:

- [JDK 17](https://www.oracle.com/java/technologies/downloads/)
- [Maven 3](https://maven.apache.org)
- [Spring Boot 3](https://start.spring.io/)
- Check the POM XML file for libraries used

# Running the application locally
Clone the project and use Maven to build 

```shell
mvn clean install
```

There are several ways to run a Spring Boot application on your local machine. 

Alternatively you can use this command

```shell
mvn spring-boot:run
```

You can also find the Jar file in this location

```console
..\FinBankApp\target\FinBankApp-0.0.1-SNAPSHOT.jar
```

# Features
- These services can perform
1. UserInfo CRUD operations -- Check the com.example.model.UserInfo -- to see the UserInfo entity

# END


