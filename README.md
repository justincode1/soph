# DSViper Android Python Tools

## 🐍 Main Python Framework Tools:

### 1. **dsviper_android.py** (45KB)
- Main DSViper Android framework
- Generates Android APKs from raw payloads
- Supports multiple Android techniques

### 2. **run_technique_11.py** (6KB)  
- Technique 11 (Android Indirect Syscall) executor
- Specialized for ARM64 Android targets

### 3. **requirements.txt**
- Python dependencies for the framework

## 🚀 Quick Usage:

```bash
# Install dependencies
pip3 install -r requirements.txt

# Generate APK from your msfvenom payload
python3 dsviper_android.py --technique 11 --payload ../payloads/reverse_shell_arm64.bin

# Run Technique 11 specifically
python3 run_technique_11.py --payload ../payloads/reverse_shell_arm64.bin
```

## 📱 Output:
- Generates signed Android APK files
- Ready for installation via ADB
- Embedded with your msfvenom payload

