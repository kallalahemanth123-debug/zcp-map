plugins {
    alias(libs.plugins.kotlin.jvm)
}

dependencies {
    api(project(":core:mesh"))
    api(libs.kotlinx.coroutines.core)
    api(libs.kotlinx.serialization.json)
    testImplementation(testFixtures(project(":core:mesh")))
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlin.test.junit)
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}
