[![GitHub Actions CI](https://github.com/JetBrains/jvm-native-trusted-roots/actions/workflows/maven.yml/badge.svg)](https://github.com/JetBrains/jvm-native-trusted-roots/actions/workflows/maven.yml)

# jvm-native-trusted-roots
Platform-Native Trusted Certificates Handling

Retrieves trusted certificates from the operating system using platform-specific APIs

## Usage

Call `org.jetbrains.nativecerts.NativeTrustedCertificates.getCustomOsSpecificTrustedCertificates`

See javadoc at [NativeTrustedCertificates.java](https://github.com/JetBrains/jvm-native-trusted-roots/blob/trunk/src/main/java/org/jetbrains/nativecerts/NativeTrustedCertificates.java)

## Testing

Some tests on Windows/Mac require a user to confirm modification of the trust store, so please run tests locally with system property `manual.test` set to `true`:

```
mvn package -Dmanual.test=true
```
