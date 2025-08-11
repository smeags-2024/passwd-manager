# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-08-11

### Added
- **Multi-Encryption Support**: AES-256-CBC, ChaCha20-Poly1305, and AES-256-GCM encryption methods
- **Modern Qt6 GUI**: Clean and intuitive graphical interface with theme support
- **Advanced Security Features**:
  - PBKDF2, Argon2-style, and Scrypt-style key derivation functions
  - Encryption-optimized password generation algorithms
  - Secure memory handling and cleanup
  - Master password protection with configurable security settings
- **Comprehensive Build System**:
  - Automated build script (`build.sh`) with dependency detection
  - Debug mode support (`--debug` flag) for development
  - Cross-platform compatibility (Linux, Windows, macOS)
  - Complete installation and uninstallation functionality
- **User Experience Features**:
  - Smart database management with project-directory defaults
  - Advanced search and filtering capabilities
  - Clipboard integration for easy credential copying
  - Auto-lock feature with configurable timeout
  - Settings dialog with comprehensive preference management
- **Documentation**: Extensive README, QUICKSTART guide, and inline documentation
- **Backward Compatibility**: Automatic detection and fallback for legacy database formats

### Technical Details
- **Languages**: C++17 with Qt6 framework
- **Encryption**: OpenSSL integration for cryptographic operations
- **Build Systems**: CMake and Make support
- **Package Managers**: Automatic detection (apt, dnf, pacman, zypper)
- **Security**: No network connectivity, local data storage only

### Security
- All sensitive data encrypted with industry-standard algorithms
- Secure random salt and IV generation
- Memory protection and automatic cleanup
- Configurable password strength requirements

---

## Future Releases

### Planned Features
- Import/Export functionality for database portability
- Additional encryption algorithms
- Enhanced password strength analysis
- Plugin system for extensions
- Mobile platform support

### Security Enhancements
- Hardware security module (HSM) support
- Two-factor authentication options
- Biometric authentication integration
- Advanced audit logging
