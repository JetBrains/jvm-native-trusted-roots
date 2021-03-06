[![GitHub Actions CI](https://github.com/JetBrains/jvm-native-trusted-roots/actions/workflows/maven.yml/badge.svg)](https://github.com/JetBrains/jvm-native-trusted-roots/actions/workflows/maven.yml) [![Space](https://img.shields.io/badge/dynamic/xml?color=orange&label=Maven%20intellij-dependencies&query=//metadata/versioning/latest&url=https:%2F%2Fpackages.jetbrains.team%2Fmaven%2Fp%2Fij%2Fintellij-dependencies%2Forg%2Fjetbrains%2Fnativecerts%2Fjvm-native-trusted-roots%2Fmaven-metadata.xml)](https://packages.jetbrains.team/maven/p/ij/intellij-dependencies)

# jvm-native-trusted-roots
Platform-Native Trusted Certificates Handling

Retrieves trusted certificates from the operating system using platform-specific APIs

## Usage

* add maven repository [intellij-dependencies](https://packages.jetbrains.team/maven/p/ij/intellij-dependencies)
* reference package `org.jetbrains.nativecerts:jvm-native-trusted-roots:VERSION`, set `VERSION` to the value displayed in this README's badge.
* call `org.jetbrains.nativecerts.NativeTrustedCertificates.getCustomOsSpecificTrustedCertificates`

See javadoc at [NativeTrustedCertificates.java](https://github.com/JetBrains/jvm-native-trusted-roots/blob/trunk/src/main/java/org/jetbrains/nativecerts/NativeTrustedCertificates.java)

## Testing

Some tests on Windows/Mac require a user to confirm modification of the trust store, so please run tests locally with system property `manual.test` set to `true`:

```
mvn package -Dmanual.test=true
```

## Releasing a new version (JetBrains internal only)

Run job at [Publish jvm-native-trusted-roots @ Space](https://jetbrains.team/p/ij/automation/jobs/history/1ydHvJ2EWAKP)