# Password Manager

A secure graphical password manager built with C++ and Qt6. This application provides encrypted storage for your passwords with a user-friendly interface and advanced security features.

## Features

### 🔒 Advanced Security
- **Multiple Encryption Methods**: Choose from AES-256-CBC, ChaCha20-Poly1305, or AES-256-GCM
- **Encryption-Specific Password Generation**: Passwords optimized for each encryption algorithm
- **Advanced Key Derivation**: PBKDF2, Argon2-style, and Scrypt-style key derivation
- **Master Password Protection**: Access controlled by a single master password
- **Backward Compatibility**: Automatic fallback for legacy databases
- **Secure Memory Handling**: Proper memory cleanup and protection

### 🎨 User Interface
- **Modern Qt6 GUI**: Clean and intuitive interface
- **Configurable Themes**: System, Dark, and Light theme options
- **Settings Dialog**: Comprehensive preference management
- **Password Strength Indicator**: Real-time password quality assessment
- **Responsive Design**: Adaptive layout for different screen sizes

### 🛠 Functionality
- **Smart Database Management**: Project-directory defaults with user choice options
- **Advanced Search**: Quick filtering across all entry fields
- **Encryption-Optimized Password Generation**: Unique algorithms for each encryption method
- **Clipboard Integration**: One-click copy for usernames and passwords
- **Auto-lock Feature**: Configurable timeout for enhanced security
- **Backup Management**: Automatic backup options with retention settings

### 🚀 Enhanced Features
- **Cross-platform**: Works on Linux, Windows, and macOS
- **Flexible Storage**: Choose database location or use project defaults
- **Import/Export**: Data portability with configurable paths
- **Logging System**: Comprehensive application logging
- **Error Recovery**: Graceful handling of encryption failures

## Security Features

### Encryption Methods
- **AES-256-CBC**: Industry-standard encryption with PBKDF2 key derivation (10k iterations)
- **ChaCha20-Poly1305**: Modern stream cipher with Argon2-style key derivation (200k iterations)
- **AES-256-GCM**: Authenticated encryption with Scrypt-style key derivation (300k iterations)
- **XOR Legacy**: Basic fallback encryption (not recommended for new databases)

### Password Generation
- **AES-Optimized**: Base64-like character set for optimal AES performance (20 chars)
- **ChaCha20-Optimized**: Extended ASCII with XOR mixing for maximum entropy (24 chars)
- **GCM-Optimized**: Cryptographically strong with maximum character diversity (32 chars)
- **Legacy**: Standard secure generation for backward compatibility (16 chars)

### Security Features
- **Salt-based Authentication**: Unique salt generation for each database
- **Secure Memory Handling**: Automatic cleanup of sensitive data
- **No Network Access**: All data stays completely local
- **Configurable Security**: Adjustable password requirements and timeouts
- **Backward Compatibility**: Automatic detection and fallback for legacy formats

## Requirements

### System Requirements
- Linux (Ubuntu 20.04+ recommended), Windows 10+, or macOS 10.15+
- Qt6 development libraries
- OpenSSL 1.1.1+ or 3.0+
- CMake 3.16+ or Make
- GCC 7+ with C++17 support (or equivalent compiler)

### Dependencies
- Qt6Core, Qt6Widgets, Qt6Gui
- OpenSSL (libssl-dev, openssl-devel)
- pkg-config (for OpenSSL detection)

## Quick Start

### Automated Installation (Linux)

The build script automatically detects your package manager and installs dependencies:

```bash
# Clone or download the project
cd passwd-manager

# Run the automated build script
./build.sh

# Or for manual dependency installation:
./build.sh --install-deps
```

### Manual Installation

#### Ubuntu/Debian:
```bash
# Install all dependencies including OpenSSL
sudo apt update
sudo apt install build-essential cmake qt6-base-dev qt6-tools-dev qt6-tools-dev-tools libssl-dev pkg-config

# Build the application
make all
```

#### Fedora/RHEL:
```bash
sudo dnf install gcc-c++ cmake qt6-qtbase-devel qt6-qttools-devel openssl-devel pkgconf-pkg-config
make all
```

#### Arch Linux:
```bash
sudo pacman -S gcc cmake qt6-base qt6-tools openssl pkg-config
make all
```

## Installation Options

### Option 1: Using Make (Recommended)

1. **Install dependencies**:
```bash
make deps  # Auto-detects your system
```

2. **Build the application**:
```bash
make all
```

3. **Install to system** (optional):
```bash
make install  # Installs to /usr/local/bin/
```

4. **Run the application**:
```bash
# If installed to system:
password-manager

# Or run directly from build directory:
make run
# The executable will be at: build/bin/password-manager
```

### Option 2: Using CMake

1. **Build with CMake**:
```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

2. **Run the application**:
```bash
./bin/PasswordManager
```

#### Option 3: Automated Build Script

The easiest way to build and install the Password Manager is using the provided build script:

```bash
# Full setup (install dependencies, build, and install)
./build.sh --all

# Or step by step
./build.sh --deps              # Install dependencies
./build.sh --build cmake       # Build with CMake
./build.sh --install           # Install system-wide

# Build with Make instead
./build.sh --build make

# Debug build for development
./build.sh --debug --build cmake
./build.sh --debug --build make

# View all options
./build.sh --help
```

### Clean Launcher (Optional)

For a cleaner experience without Qt debug messages:

```bash
# Use the clean launcher script
./run_clean.sh

# Or run directly with clean output
export QT_LOGGING_RULES="*.debug=false;qt.qpa.xcb.debug=false"
./build/bin/password-manager
```

## Uninstalling

### Method 1: Using Build Script (Recommended)
```bash
# Interactive uninstall with user data preservation option
./build.sh --uninstall

# This will:
# 1. Remove the system installation (/usr/local/bin/password-manager)
# 2. Remove the desktop entry from applications menu
# 3. Update the applications menu
# 4. Ask if you want to remove user data and settings
# 5. Provide clear feedback about what was removed
```

### Method 2: Using Make
```bash
# Remove the installed binary and desktop entry
make uninstall

# Or manually:
sudo rm -f /usr/local/bin/password-manager
rm -f ~/.local/share/applications/password-manager.desktop
```

### Complete Removal (Optional)
```bash
# Method 1: Use build script interactive removal
./build.sh --uninstall
# Then choose 'y' when asked about user data removal

# Method 2: Manual removal
# Remove user data (WARNING: This deletes your password databases!)
rm -rf ~/.local/share/PasswordManager/

# Remove user settings
rm -rf ~/.config/PasswordManager/

# Remove project build files
make clean
```

**⚠️ Warning**: Complete removal will delete all your password databases. Make sure to backup your data before removing user directories.

## Usage

### First Run
1. Launch the application: `./build/bin/password-manager`
2. Choose **File → New Database** to create your first password database
3. The database will be created in the project directory by default
4. Set a strong master password (minimum 6 characters recommended)
5. Start adding your password entries

### Database Management
- **New Database**: Creates a database in the project directory
- **Open Database**: Browse to open any existing database file
- **Close Database**: Safely close the current database
- **Location Choice**: Option to create databases in custom locations

### Adding Password Entries
1. Click the **"Add"** button
2. Fill in the entry details:
   - **Title** (required): A descriptive name for the entry
   - **Username**: Account username or email
   - **Password**: Use **"Generate"** for secure random passwords
   - **URL**: Website or application URL
   - **Notes**: Additional information or security questions
3. Click **"Save"** to store the entry

### Managing Entries
- **Edit**: Select an entry and click **"Edit"** to modify details
- **Delete**: Select an entry and click **"Delete"** (with confirmation)
- **Search**: Use the search box to filter entries by title, username, or URL
- **Copy Credentials**: Use **"Copy Username"** and **"Copy Password"** buttons
- **Password Visibility**: Toggle password visibility with the checkbox

### Settings & Configuration

Access **File → Settings** to configure:

#### General Settings
- **Theme**: Choose between System, Dark, or Light themes
- **Remember Last Database**: Automatically reopen your last database
- **Password Strength Indicator**: Show/hide password quality feedback

#### Security Settings
- **Minimum Password Length**: Enforce password length requirements (4-50 characters)
- **Auto-lock**: Automatically lock the application after inactivity
- **Lock Timeout**: Configure auto-lock delay (1-240 minutes)
- **Encryption Method**: Choose between:
  - **AES-256-CBC (Standard)**: Fast and secure for most users
  - **ChaCha20-Poly1305**: Modern stream cipher resistant to timing attacks
  - **AES-256-GCM**: Authenticated encryption that prevents tampering
  - **XOR (Legacy)**: Not recommended for new databases

#### Backup & Export Settings
- **Automatic Backups**: Enable scheduled database backups
- **Backup Retention**: Set how long to keep backup files (1-365 days)
- **Default Export Path**: Set preferred location for exported data

### Password Security Features
- **Encryption-Specific Generation**: Passwords optimized for your chosen encryption method
  - **AES-256**: Base64-like characters for optimal performance
  - **ChaCha20**: Extended ASCII with enhanced entropy
  - **AES-GCM**: Maximum character diversity for authenticated encryption
- **Strength Testing**: Real-time password strength analysis in settings
- **Secure Generation**: Built-in cryptographically secure password generator
- **Clipboard Security**: Automatic clipboard clearing after copying passwords
- **Memory Protection**: Sensitive data is cleared from memory after use

### Security Best Practices
- **Master Password**: Use a strong, unique master password with mixed characters
- **Regular Backups**: Keep secure backups of your database file
- **Screen Privacy**: Use "Show Password" only when necessary
- **Encryption-Optimized Passwords**: Use the built-in generator for encryption-specific passwords
- **Auto-lock**: Enable auto-lock for shared computers
- **Choose Strong Encryption**: Use ChaCha20-Poly1305 or AES-256-GCM for maximum security
- **Update Regularly**: Keep the application updated for latest security features

## Project Structure

```
passwd-manager/
├── build.sh                    # Automated build script
├── run_clean.sh                # Clean launcher (suppresses Qt debug output)
├── CMakeLists.txt              # CMake build configuration  
├── Makefile                    # Make build configuration
├── README.md                   # This documentation
├── .gitignore                  # Git ignore rules
├── build/                      # Build output directory
│   └── bin/                    # Compiled executables
├── data/                       # Default database storage
├── include/                    # Header files
│   ├── crypto_utils.h          # Encryption utilities (AES-256, ChaCha20, AES-GCM)
│   ├── logger.h                # Logging system
│   ├── main_window.h           # GUI main window
│   ├── password_database.h     # Database management
│   ├── password_entry.h        # Password entry structure
│   ├── settings.h              # Settings management
│   └── settings_dialog.h       # Settings GUI dialog
└── src/                        # Source files
    ├── crypto_utils.cpp        # Encryption implementation
    ├── logger.cpp              # Logging implementation
    ├── main.cpp                # Application entry point
    ├── main_window.cpp         # GUI implementation
    ├── password_database.cpp   # Database implementation
    ├── password_entry.cpp      # Entry structure implementation
    ├── settings.cpp            # Settings implementation
    └── settings_dialog.cpp     # Settings dialog implementation
```

## Database Format & Security

### Encryption Details
- **Algorithm**: AES-256-CBC with OpenSSL backend
- **Key Derivation**: PBKDF2 with SHA-256, 10,000 iterations
- **Salt**: Unique 32-byte salt per database
- **IV**: Random 16-byte initialization vector per encryption
- **Backward Compatibility**: Automatic detection and fallback for legacy XOR encryption

### File Structure
```
Database File Format:
SALT:<base64-encoded-salt>
HASH:<pbkdf2-password-hash>
ENTRY:<aes-encrypted-entry-data>
ENTRY:<aes-encrypted-entry-data>
...
```

### Storage Locations
- **Development Mode**: `project-directory/data/passwords.db`
- **System Installation**: `~/.local/share/PasswordManager/passwords.db`
- **Custom Location**: User-selectable via file dialog
- **Settings File**: `~/.config/PasswordManager/settings.ini`

## Development

### Building for Development
```bash
# Debug build with symbols using build script (recommended)
./build.sh --debug --build cmake

# Debug build with Make via build script
./build.sh --debug --build make

# Manual debug build with Make
make DEBUG=1 VERBOSE=1

# Manual debug build with CMake
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_VERBOSE_MAKEFILE=ON ..
make VERBOSE=1

# Regular build with build script
./build.sh --build cmake

# Build with Make via build script
./build.sh --build make

# Clean build
make clean
./build.sh --clean
```

Debug builds include:
- Debug symbols for GDB debugging
- Verbose compilation output  
- No optimization (-O0) for easier debugging
- Additional debug preprocessor definitions

### Code Architecture
- **CryptoUtils**: Advanced encryption/decryption with OpenSSL integration
- **PasswordEntry**: Structured data representation with serialization
- **PasswordDatabase**: Secure database operations with AES encryption
- **MainWindow**: Qt6-based GUI with modern interface design
- **Settings**: Comprehensive configuration management system
- **Logger**: Multi-level logging with file and console output

### Key Technologies
- **C++17**: Modern C++ standards with smart pointers and STL
- **Qt6**: Cross-platform GUI framework with signals/slots
- **OpenSSL**: Industry-standard cryptographic library
- **CMake/Make**: Dual build system support for flexibility

## Troubleshooting

### Common Issues

1. **Build Dependencies Missing**:
   ```bash
   # Try automated dependency installation
   ./build.sh --install-deps
   
   # Or install manually for your distribution
   make deps  # Ubuntu/Debian
   ```

2. **OpenSSL Not Found**:
   ```bash
   # Ubuntu/Debian
   sudo apt install libssl-dev pkg-config
   
   # Fedora/RHEL  
   sudo dnf install openssl-devel pkgconf-pkg-config
   
   # Arch Linux
   sudo pacman -S openssl pkg-config
   ```

3. **Qt6 Not Found**:
   - Ensure Qt6 development packages are installed (not just runtime)
   - Verify MOC (Meta Object Compiler) is available
   - Check that qmake points to Qt6 version

4. **Build Fails with C++17 Errors**:
   - Update GCC to version 7 or later
   - Ensure CMake is 3.16 or newer
   - Check that C++17 standard is supported

5. **Application Won't Start**:
   - Verify Qt6 runtime libraries are installed
   - Check file permissions for the application directory
   - Ensure OpenSSL runtime libraries are available

6. **Database Issues**:
   - **Cannot open database**: Verify correct master password
   - **Corruption detected**: Check file permissions and disk space
   - **Legacy database**: Application automatically handles XOR→AES migration

7. **Performance Issues**:
   - Large databases (1000+ entries) may take longer to load
   - Enable auto-backups for data safety
   - Consider database optimization for very large datasets

### Debug Information

Enable detailed logging by setting environment variables:
```bash
export QT_LOGGING_RULES="*=true"
./build/bin/password-manager
```

Check log files in:
- **Development**: `./logs/password-manager.log`
- **System**: `~/.local/share/PasswordManager/logs/`

## Security Considerations

### Current Security Measures
- **AES-256-CBC Encryption**: Industry-standard symmetric encryption
- **PBKDF2 Key Derivation**: 10,000 iterations with SHA-256 hash
- **Secure Random Generation**: OpenSSL-powered cryptographic randomness
- **Memory Protection**: Automatic cleanup of sensitive data
- **No Network Access**: All data processing stays completely local
- **Salt-based Authentication**: Unique salt per database prevents rainbow table attacks
- **Legacy Support**: Secure migration from older encryption methods

### Security Recommendations
- **Backup Strategy**: Keep encrypted backups in multiple secure locations
- **Master Password**: Use a unique, strong password not used elsewhere
- **System Security**: Keep your operating system and dependencies updated
- **Physical Security**: Secure the device where the database is stored
- **Regular Updates**: Update the application when new versions are available

### Known Limitations
- **Single Point of Failure**: Master password is the only authentication factor
- **Local Storage Only**: No cloud sync capabilities (by design)
- **Memory Dumps**: Advanced attackers with system access might extract data from memory
- **Side-channel Attacks**: Timing attacks theoretically possible on very fast systems

### For Production Use
Consider additional security measures for high-security environments:
- Hardware security modules (HSM) for key storage
- Multi-factor authentication implementation
- Database integrity verification and checksums
- Secure memory allocation libraries
- Regular security audits and penetration testing

## Contributing

This project demonstrates modern C++ development practices:

### Educational Value
- **Qt6 Framework**: Modern cross-platform GUI development
- **OpenSSL Integration**: Professional-grade cryptographic implementation
- **C++17 Features**: Smart pointers, STL containers, modern language features
- **Software Architecture**: Clean separation of concerns and modular design
- **Security Implementation**: Real-world encryption and secure coding practices

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Implement changes with proper testing
4. Ensure all security considerations are addressed
5. Submit a pull request with detailed documentation

### Code Standards
- Follow C++17 best practices
- Use Qt naming conventions for GUI components
- Implement proper error handling and logging
- Maintain backward compatibility where possible
- Document security-related code changes thoroughly

## License

This project is provided as-is for educational and practical use. Please review the code and security implementations before using in production environments.

## Version History

### v1.3.0 (Current) - Maximum Security & User Experience
- **🔐 Enhanced Encryption**: Increased PBKDF2 iterations to 100,000 for maximum security
- **📊 Real-time Password Strength**: Live password strength indicator in entry form
- **🎯 Advanced Password Generation**: Secure OpenSSL-powered password generation with customizable options
- **🔧 Improved Algorithm**: Enhanced password strength calculation with pattern detection
- **🛡️ Security Hardening**: Resistance against timing attacks and pattern analysis
- **🎨 Visual Feedback**: Color-coded strength indicators and detailed recommendations
- **⚡ Performance Optimized**: Efficient strength calculation without UI blocking
- **🔄 Seamless Integration**: Automatic strength updates during entry viewing and editing
### v1.2.0 - Enhanced Security & Features
- **🔒 AES-256 Encryption**: OpenSSL integration for professional-grade security
- **⚙️ Settings System**: Comprehensive preference management with GUI
- **🎨 Theme Support**: System, Dark, and Light theme options
- **🛡️ Password Strength**: Real-time strength analysis and recommendations
- **🔄 Auto-lock**: Configurable security timeout
- **📦 Smart Database Management**: Project-directory defaults with user choice
- **🧹 Enhanced Build**: Automated dependency installation and multi-platform support
- **📊 Advanced Logging**: Detailed application logging and error tracking
- **🔐 PBKDF2 Key Derivation**: 10,000 iterations for secure password hashing
- **🔄 Backward Compatibility**: Seamless migration from legacy XOR encryption

### v1.1.0 - Improved Security & UX
- **🔧 Better Error Handling**: Graceful encryption failure recovery
- **💾 Database Location Choice**: Flexible storage options
- **🔍 Enhanced Search**: Improved filtering and search capabilities
- **🎯 UI Improvements**: Better layout and user experience
- **🛠️ Build System**: Enhanced Makefile and CMake configurations

### v1.0.0 - Initial Release
- **🔐 Basic Encryption**: XOR cipher with base64 encoding
- **🖥️ Qt6 GUI**: Clean and intuitive interface
- **💾 Database Management**: Secure local storage
- **🔑 Password Generation**: Built-in secure password generator
- **🔍 Search Functionality**: Quick entry filtering
- **📋 Clipboard Integration**: Easy credential copying

## Quick Reference

### Essential Commands
```bash
# Quick start (run locally)
./build.sh --build cmake && ./build/bin/PasswordManager

# Full setup (install system-wide)
./build.sh --all

# Development build with debug symbols
./build.sh --debug --build cmake

# Install dependencies only  
./build.sh --deps

# Install to system (alternative)
make install

# Run from system installation
password-manager

# Clean launcher (no debug output)
./run_clean.sh

# Development build with debug symbols
make debug

# Clean everything
make clean

# Uninstall from system (interactive)
./build.sh --uninstall

# Uninstall from system (make only)
make uninstall
```

### Default Locations
- **Executable**: `build/bin/password-manager` (local) or `/usr/local/bin/password-manager` (system)
- **Database**: `data/passwords.db` (project directory) or `~/.local/share/PasswordManager/passwords.db` (system)
- **Settings**: `~/.config/PasswordManager/settings.ini`
- **Logs**: `logs/password-manager.log` (local) or `~/.local/share/PasswordManager/logs/` (system)

### Security Features Summary
✅ AES-256-CBC encryption with OpenSSL  
✅ PBKDF2 key derivation (10,000 iterations)  
✅ Secure random salt and IV generation  
✅ Master password protection  
✅ Memory cleanup and protection  
✅ No network connectivity  
✅ Configurable auto-lock  
✅ Password strength validation  
✅ Legacy database migration
