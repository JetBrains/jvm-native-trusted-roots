job("Publish jvm-native-trusted-roots") {
    startOn {
        gitPush {
            enabled = false
        }
    }

    container("maven:3-openjdk-11") {
        env["REPOSITORY_URL"] = "https://packages.jetbrains.team/maven/p/ij/intellij-dependencies"

        shellScript {
            content = """
                set -x -e -u
                mvn versions:set -DnewVersion=1.0.${'$'}JB_SPACE_EXECUTION_NUMBER
                mvn deploy -X -s settings.xml \
                    -DrepositoryUrl=${'$'}REPOSITORY_URL \
                    -DspaceUsername=${'$'}JB_SPACE_CLIENT_ID \
                    -DspacePassword=${'$'}JB_SPACE_CLIENT_SECRET
            """
        }
    }
}