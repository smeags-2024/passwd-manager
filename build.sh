#!/bin/bash

# Password Manager Build Script
# This script automates the build process for the Password Manager application

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect package manager
detect_package_manager() {
    if command_exists apt; then
        echo "apt"
    elif command_exists dnf; then
        echo "dnf"
    elif command_exists yum; then
        echo "yum"
    elif command_exists pacman; then
        echo "pacman"
    elif command_exists zypper; then
        echo "zypper"
    else
        echo "unknown"
    fi
}

# Function to install dependencies
install_dependencies() {
    local pm=$(detect_package_manager)
    
    print_status "Detected package manager: $pm"
    
    case $pm in
        "apt")
            print_status "Installing dependencies with apt..."
            sudo apt update
            sudo apt install -y build-essential cmake qt6-base-dev qt6-tools-dev qt6-tools-dev-tools libssl-dev pkg-config
            ;;
        "dnf")
            print_status "Installing dependencies with dnf..."
            sudo dnf install -y gcc-c++ cmake qt6-qtbase-devel qt6-qttools-devel openssl-devel pkgconf-pkg-config
            ;;
        "yum")
            print_status "Installing dependencies with yum..."
            sudo yum install -y gcc-c++ cmake qt6-qtbase-devel qt6-qttools-devel openssl-devel pkgconfig
            ;;
        "pacman")
            print_status "Installing dependencies with pacman..."
            sudo pacman -S --needed gcc cmake qt6-base qt6-tools openssl pkg-config
            ;;
        "zypper")
            print_status "Installing dependencies with zypper..."
            sudo zypper install -y gcc-c++ cmake qt6-base-devel qt6-tools-devel libopenssl-devel pkg-config
            ;;
        *)
            print_error "Unknown package manager. Please install dependencies manually:"
            echo "  - build-essential/gcc-c++"
            echo "  - cmake"
            echo "  - qt6-base-dev/qt6-qtbase-devel"
            echo "  - qt6-tools-dev/qt6-qttools-devel"
            echo "  - libssl-dev/openssl-devel"
            echo "  - pkg-config"
            exit 1
            ;;
    esac
}

# Function to build with CMake
build_cmake() {
    local debug_flag="$1"
    
    if [ "$debug_flag" = "debug" ]; then
        print_status "Building with CMake (Debug mode)..."
    else
        print_status "Building with CMake..."
    fi
    
    if [ -d "build" ]; then
        print_warning "Build directory exists. Cleaning..."
        rm -rf build
    fi
    
    mkdir build
    cd build
    
    if [ "$debug_flag" = "debug" ]; then
        print_status "Configuring with debug symbols and verbose output..."
        cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_VERBOSE_MAKEFILE=ON ..
        make -j$(nproc) VERBOSE=1
    else
        cmake ..
        make -j$(nproc)
    fi
    
    cd ..
    print_success "CMake build completed!"
}

# Function to build with Make
build_make() {
    local debug_flag="$1"
    
    if [ "$debug_flag" = "debug" ]; then
        print_status "Building with Make (Debug mode)..."
    else
        print_status "Building with Make..."
    fi
    
    make clean 2>/dev/null || true
    
    if [ "$debug_flag" = "debug" ]; then
        print_status "Building with debug symbols and verbose output..."
        make -j$(nproc) DEBUG=1 VERBOSE=1
    else
        make -j$(nproc)
    fi
    
    print_success "Make build completed!"
}

# Function to run tests (placeholder)
run_tests() {
    print_status "Running tests..."
    # Add test commands here when tests are implemented
    print_success "Tests completed (no tests implemented yet)!"
}

# Function to create desktop entry
create_desktop_entry() {
    local install_dir="$1"
    local desktop_file="$HOME/.local/share/applications/password-manager.desktop"
    
    print_status "Creating desktop entry..."
    
    mkdir -p "$(dirname "$desktop_file")"
    
    cat > "$desktop_file" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Password Manager
Comment=Secure password manager with encryption
Exec=$install_dir/password-manager
Icon=dialog-password
Terminal=false
Categories=Utility;Security;
Keywords=password;security;encryption;
EOF
    
    chmod +x "$desktop_file"
    print_success "Desktop entry created at $desktop_file"
}

# Function to install the application
install_app() {
    local build_method="$1"
    
    if [ "$build_method" = "cmake" ]; then
        if [ -f "build/bin/PasswordManager" ]; then
            print_status "Installing application..."
            sudo cp build/bin/PasswordManager /usr/local/bin/password-manager
            sudo chmod +x /usr/local/bin/password-manager
            create_desktop_entry "/usr/local/bin"
            print_success "Application installed to /usr/local/bin/password-manager"
        else
            print_error "Build artifact not found. Build first."
            exit 1
        fi
    elif [ "$build_method" = "make" ]; then
        if [ -f "build/bin/password-manager" ]; then
            print_status "Installing application..."
            sudo cp build/bin/password-manager /usr/local/bin/
            sudo chmod +x /usr/local/bin/password-manager
            create_desktop_entry "/usr/local/bin"
            print_success "Application installed to /usr/local/bin/password-manager"
        else
            print_error "Build artifact not found. Build first."
            exit 1
        fi
    fi
}

# Function to show usage
show_usage() {
    echo "Password Manager Build Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -d, --deps          Install dependencies only"
    echo "  -b, --build [TYPE]  Build the application (cmake|make)"
    echo "  --debug             Enable debug mode for builds (verbose output, debug symbols)"
    echo "  -i, --install       Install the application system-wide"
    echo "  -u, --uninstall     Uninstall the application from system"
    echo "  -t, --test          Run tests"
    echo "  -c, --clean         Clean build artifacts"
    echo "  --all               Install deps, build, and install (equivalent to -d -b -i)"
    echo ""
    echo "Examples:"
    echo "  $0 --all                    # Full setup"
    echo "  $0 -d -b cmake -i           # Install deps, build with CMake, install"
    echo "  $0 -b make --debug          # Build with Make in debug mode"
    echo "  $0 --debug -b cmake         # Build with CMake in debug mode"
    echo "  $0 --uninstall              # Uninstall from system"
    echo ""
}

# Function to clean build artifacts
clean_build() {
    print_status "Cleaning build artifacts..."
    rm -rf build
    make clean 2>/dev/null || true
    print_success "Build artifacts cleaned!"
}

# Function to uninstall the application
uninstall_app() {
    print_status "Uninstalling Password Manager..."
    
    # Check if the application is installed
    if [ -f "/usr/local/bin/password-manager" ]; then
        print_status "Removing system installation..."
        if sudo rm -f /usr/local/bin/password-manager; then
            print_success "Password Manager removed from /usr/local/bin/"
        else
            print_error "Failed to remove system installation"
            return 1
        fi
    else
        print_warning "Password Manager is not installed in /usr/local/bin/"
    fi
    
    # Remove desktop entry
    local desktop_file="$HOME/.local/share/applications/password-manager.desktop"
    if [ -f "$desktop_file" ]; then
        print_status "Removing desktop entry..."
        if rm -f "$desktop_file"; then
            print_success "Desktop entry removed from applications menu"
        else
            print_warning "Failed to remove desktop entry"
        fi
    else
        print_status "No desktop entry found to remove"
    fi
    
    # Update desktop database to refresh the applications menu
    if command_exists update-desktop-database; then
        print_status "Updating applications menu..."
        if update-desktop-database "$HOME/.local/share/applications/" 2>/dev/null; then
            print_success "Applications menu updated"
        else
            print_status "Applications menu update completed"
        fi
    else
        print_status "Desktop database update tool not available (this is normal)"
    fi
    
    echo ""  # Add blank line for better readability
    # Ask user if they want to remove user data
    print_warning "User data and settings are preserved by default."
    echo "Do you want to remove ALL user data and settings? (y/N)"
    echo "  This will delete:"
    echo "  - Password databases: ~/.local/share/PasswordManager/"
    echo "  - Settings: ~/.config/PasswordManager/"
    echo "  - Logs and backups"
    echo ""
    echo -n "Your choice: "
    read -r response
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        print_status "User selected: YES - Removing all user data..."
        echo ""
        print_warning "Removing ALL user data..."
        
        if [ -d "$HOME/.local/share/PasswordManager" ]; then
            rm -rf "$HOME/.local/share/PasswordManager"
            print_status "Removed user data directory"
        fi
        
        if [ -d "$HOME/.config/PasswordManager" ]; then
            rm -rf "$HOME/.config/PasswordManager"
            print_status "Removed user settings directory"
        fi
        
        echo ""
        print_success "Complete uninstallation finished!"
        print_status "Password Manager has been completely removed from your system."
    else
        print_status "User selected: NO - Preserving user data"
        echo ""
        print_success "Uninstallation complete! User data preserved."
        print_status "Password Manager removed from system but user data kept safe."
        print_status "To remove user data later:"
        print_status "  rm -rf ~/.local/share/PasswordManager/"
        print_status "  rm -rf ~/.config/PasswordManager/"
    fi
}

# Main script logic
main() {
    local install_deps=false
    local build_method=""
    local install_app_flag=false
    local uninstall_flag=false
    local run_tests_flag=false
    local clean_flag=false
    local full_setup=false
    local debug_mode=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -d|--deps)
                install_deps=true
                shift
                ;;
            -b|--build)
                if [[ -n "$2" && "$2" != -* ]]; then
                    build_method="$2"
                    shift 2
                else
                    build_method="cmake"  # Default to cmake
                    shift
                fi
                ;;
            --debug)
                debug_mode=true
                print_status "Debug mode enabled"
                shift
                ;;
            -i|--install)
                install_app_flag=true
                shift
                ;;
            -u|--uninstall)
                uninstall_flag=true
                shift
                ;;
            -t|--test)
                run_tests_flag=true
                shift
                ;;
            -c|--clean)
                clean_flag=true
                shift
                ;;
            --all)
                full_setup=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # If no arguments provided, show usage
    if [[ $# -eq 0 && "$install_deps" == false && "$build_method" == "" && "$install_app_flag" == false && "$uninstall_flag" == false && "$run_tests_flag" == false && "$clean_flag" == false && "$full_setup" == false ]]; then
        show_usage
        exit 1
    fi
    
    # Handle full setup
    if [ "$full_setup" = true ]; then
        install_deps=true
        build_method="cmake"
        install_app_flag=true
    fi
    
    print_status "Password Manager Build Script Starting..."
    
    # Handle uninstall if requested (do this first and exit)
    if [ "$uninstall_flag" = true ]; then
        uninstall_app
        exit 0
    fi
    
    # Clean if requested
    if [ "$clean_flag" = true ]; then
        clean_build
    fi
    
    # Install dependencies
    if [ "$install_deps" = true ]; then
        install_dependencies
    fi
    
    # Build application
    if [ -n "$build_method" ]; then
        local debug_arg=""
        if [ "$debug_mode" = true ]; then
            debug_arg="debug"
        fi
        
        case $build_method in
            "cmake")
                build_cmake "$debug_arg"
                ;;
            "make")
                build_make "$debug_arg"
                ;;
            *)
                print_error "Unknown build method: $build_method"
                print_error "Supported methods: cmake, make"
                exit 1
                ;;
        esac
    fi
    
    # Run tests
    if [ "$run_tests_flag" = true ]; then
        run_tests
    fi
    
    # Install application
    if [ "$install_app_flag" = true ]; then
        if [ -n "$build_method" ]; then
            install_app "$build_method"
        else
            print_error "Cannot install without building first. Use -b option."
            exit 1
        fi
    fi
    
    print_success "Build script completed successfully!"
    
    if [ "$install_app_flag" = true ]; then
        echo ""
        print_status "You can now run the application with:"
        echo "  password-manager"
        echo ""
        print_status "Or find it in your applications menu as 'Password Manager'"
    fi
}

# Check if script is run from the correct directory
if [ ! -f "CMakeLists.txt" ] || [ ! -f "Makefile" ]; then
    print_error "This script must be run from the password manager project root directory."
    exit 1
fi

# Run main function with all arguments
main "$@"
