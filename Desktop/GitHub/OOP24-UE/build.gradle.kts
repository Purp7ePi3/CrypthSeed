plugins {
    java
    application
}

group = "it.unibo.exam"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    // Aggiungi eventuali dipendenze qui
}

application {
    mainClass.set("main.java.it.unibo.exam.Main")
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}

sourceSets {
    main {
        java {
            setSrcDirs(listOf("src/main/java"))
        }
    }
}
