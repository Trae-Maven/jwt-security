# Jwt Security

A lightweight and flexible JWT authentication and security library for Java.

Jwt Security provides simple utilities and helpers for generating, validating, and managing JSON Web Tokens in Java applications.

The library is designed to be lightweight, fast, and easy to integrate into existing Spring-based Java applications.

Built for modern Java (Java 21+) and designed to integrate seamlessly with existing Spring infrastructure.

---

## Features

- JWT token generation
- JWT token validation
- Token parsing and claim access
- Lightweight security utilities
- Minimal dependencies
- Designed for modern Java (Java 21+)
- Easy integration into Spring applications

---

## Requirements

Jwt Security is designed for Spring-based web applications.

Your project must already include the following dependencies (these are typically already included in most Spring Boot applications):

```xml
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-context</artifactId>
    <version>7.0.3</version>
</dependency>

<dependency>
    <groupId>jakarta.servlet</groupId>
    <artifactId>jakarta.servlet-api</artifactId>
    <version>6.0.0</version>
</dependency>
```

These dependencies are marked as **provided** inside Jwt Security because they are expected to already exist in your application.

---

## Built-in Dependencies

Jwt Security includes several dependencies that are automatically included when you install the library.

- [Utilities](https://github.com/Trae-Maven/utilities) – Shared helper classes and performance-focused utilities used internally by the framework.

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.5</version>
</dependency>

<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.12.5</version>
</dependency>

<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.12.5</version>
</dependency>
```

These dependencies are automatically included when installing Jwt Security and do not need to be added manually.

---

## Installation

Add the dependency to your Maven project:

```xml
<dependency>
    <groupId>io.github.trae</groupId>
    <artifactId>jwt-security</artifactId>
    <version>0.0.1</version>
</dependency>
```
