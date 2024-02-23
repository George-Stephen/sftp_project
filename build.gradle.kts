plugins {
    id("java")
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral();


}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.9.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    implementation("org.bouncycastle:bcprov-jdk15on:1.69")
    implementation("org.bouncycastle:bcpg-jdk15on:1.69")
    implementation("org.bouncycastle:bcpkix-jdk15on:1.68")
    implementation("com.jcraft:jsch:0.1.55") // or the latest version available

}

tasks.test {
    useJUnitPlatform()
}