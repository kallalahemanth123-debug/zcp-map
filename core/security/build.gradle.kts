plugins {
    alias(libs.plugins.kotlin.jvm)
}

dependencies {
    api(project(":core:protocol"))
    api(libs.bouncycastle.prov)
    api(libs.kotlinx.serialization.json)
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit)
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}
