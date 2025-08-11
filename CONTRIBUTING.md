# Contributing to Password Manager

Thank you for your interest in contributing to this project! We welcome contributions from the community.

## Getting Started

### Prerequisites
- Linux, Windows, or macOS development environment
- Qt6 development libraries
- OpenSSL 1.1.1+ or 3.0+
- CMake 3.16+ or Make
- GCC 7+ with C++17 support (or equivalent compiler)

### Setting Up Development Environment
```bash
# Clone the repository
git clone https://github.com/smeags-2024/passwd-manager.git
cd passwd-manager

# Install dependencies (Linux example)
./build.sh --deps

# Build in debug mode for development
./build.sh --debug --build cmake
```

## How to Contribute

### Reporting Bugs
1. Check existing issues to avoid duplicates
2. Create a new issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, Qt version, compiler)
   - Debug logs if available

### Suggesting Features
1. Open an issue with the "enhancement" label
2. Describe the feature and its use case
3. Discuss implementation approach if you have ideas

### Submitting Code Changes

#### Before You Start
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make sure you can build and run the application

#### Code Guidelines
1. **Code Style**:
   - Use consistent indentation (4 spaces)
   - Follow existing naming conventions
   - Add comments for complex logic
   - Use meaningful variable and function names

2. **Security Considerations**:
   - Never hardcode passwords or keys
   - Properly handle sensitive data in memory
   - Follow secure coding practices for cryptographic functions
   - Validate all user inputs

3. **Qt6 Best Practices**:
   - Use smart pointers where appropriate
   - Follow Qt's naming conventions
   - Properly handle signals and slots
   - Ensure thread safety in multi-threaded code

#### Testing Your Changes
```bash
# Build and test your changes
./build.sh --debug --build cmake

# Run the application locally
./build/bin/PasswordManager

# Test installation and uninstallation
./build.sh --install
./build.sh --uninstall
```

#### Submitting Pull Requests
1. Ensure your code builds without warnings
2. Test thoroughly on your target platform
3. Update documentation if needed
4. Create a pull request with:
   - Clear title and description
   - Reference any related issues
   - List of changes made
   - Testing performed

## Development Workflow

### Project Structure
```
passwd-manager/
├── src/           # Source code files
├── include/       # Header files
├── build/         # Build artifacts (generated)
├── data/          # Default database location
├── logs/          # Application logs
├── CMakeLists.txt # CMake build configuration
├── Makefile       # Make build configuration
├── build.sh       # Automated build script
└── README.md      # Main documentation
```

### Key Components
- **MainWindow**: Primary GUI interface
- **PasswordDatabase**: Database management and encryption
- **CryptoUtils**: Encryption/decryption functions
- **SettingsDialog**: Application configuration
- **Logger**: Application logging system

### Encryption Implementation
- Multiple encryption methods supported
- Backward compatibility maintained
- Secure key derivation functions
- Proper salt and IV generation

## Code Review Process

1. All submissions require review
2. Maintainers will review for:
   - Code quality and style
   - Security implications
   - Performance impact
   - Documentation completeness
3. Address review feedback promptly
4. Maintain a clean commit history

## Community Guidelines

- Be respectful and constructive
- Help others learn and grow
- Focus on the technical aspects
- Follow the code of conduct (be professional)

## Questions?

If you have questions about contributing:
1. Check this document first
2. Look at existing issues and PRs
3. Open a new issue with the "question" label

Thank you for contributing to make this password manager better and more secure!
