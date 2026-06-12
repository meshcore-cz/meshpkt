# Android bindings

The Android output is built from the tiny Go package in `mobile/`. It exposes
the stable JSON dispatch boundary as:

```kotlin
Mobile.call(name: String, argsJSON: String): String
```

All packet logic stays in the root `meshpkt` package. Android callers should
pass byte arrays as lowercase hex strings inside the JSON argument array, just
like the JavaScript/WASM bindings.

## Build the AAR

Install and initialize gomobile once:

```sh
make android-init
```

Build the Android archive:

```sh
make android-aar
```

If your Android SDK is installed outside the default location, point gomobile at
it while building:

```sh
ANDROID_HOME=/path/to/android-sdk ANDROID_SDK_ROOT=/path/to/android-sdk make android-aar
```

The output is written to:

```text
dist/android/meshpkt.aar
```

You can override the Android API level if needed:

```sh
make android-aar ANDROID_API=28
```

## Add it to an Android project

Copy the AAR into your app:

```sh
mkdir -p android/app/libs
cp dist/android/meshpkt.aar android/app/libs/
```

Add it to `android/app/build.gradle.kts`:

```kotlin
dependencies {
    implementation(files("libs/meshpkt.aar"))
}
```

The generated Go Mobile class is available from Kotlin as:

```kotlin
import cz.meshcore.meshpkt.mobile.Mobile

val resultJson = Mobile.call(
    "encodeGroupText",
    """["#test","Tree","Hello from Android"]""",
)
```

## Kotlin facade

`Meshpkt.kt` is an optional convenience wrapper for Android apps. Copy it into
your app source tree, for example:

```text
android/app/src/main/java/cz/meshcore/meshpkt/Meshpkt.kt
```

Then call the higher-level helpers:

```kotlin
val packet: ByteArray = Meshpkt.encodeGroupText(
    channelName = "#test",
    sender = "Tree",
    text = "Hello mesh!",
)

val decoded = Meshpkt.decodeEnvelope(packet)
println(decoded.toString(2))
```

For operations without a dedicated helper, use the generic JSON wrapper:

```kotlin
val secret = Meshpkt.call("deriveChannelSecret", "#test")
    .getString("hex")
```
