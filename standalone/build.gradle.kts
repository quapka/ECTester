
plugins {
    application
    jacoco
    id("com.google.osdetector") version "1.7.3"
    id("com.adarshr.test-logger") version "4.0.0"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(files("$rootDir/ext/wolfcrypt-jni.jar"))
    implementation(project(":common"))

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.junit-pioneer:junit-pioneer:2.2.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
}

application {
    applicationName = "ECTesterStandalone"
    mainClass = "cz.crcs.ectester.standalone.ECTesterStandalone"
    version = "0.3.3"
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

tasks.test {
    finalizedBy(tasks.jacocoTestReport) // report is always generated after tests run
}

tasks.jacocoTestReport {
    reports {
        xml.required = true
    }
}

tasks.withType<JavaCompile> {
    if (JavaVersion.current() > JavaVersion.VERSION_1_8) {
        options.compilerArgs.addAll(arrayOf(
                "--add-modules", "jdk.crypto.ec",
                "--add-exports", "jdk.crypto.ec/sun.security.ec=ALL-UNNAMED"
        ))
    }
}

tasks.register<Exec>("libs") {
    workingDir("src/main/resources/cz/crcs/ectester/standalone/libs/jni")
    environment("PROJECT_ROOT_PATH", rootDir.absolutePath)
    if (osdetector.os == "windows") {
        commandLine("makefile.bat", "/c")
    } else if (osdetector.os == "linux"){
        commandLine("make", "-k", "-B")
    }
}

tasks.register<Jar>("uberJar") {
    archiveFileName = "ECTesterStandalone.jar"

    from(sourceSets.main.get().output)

    manifest {
        attributes["Main-Class"] = application.mainClass
    }

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it).matching { exclude("META-INF/*.DSA", "META-INF/*.SF", "META-INF/*.RSA", "META-INF/versions/*/module-info.class") } }
    })
}