# Makefile for Password Manager
# Requires Qt6 development libraries to be installed

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Iinclude
MOC = moc
QT_LIBS = -lQt6Core -lQt6Widgets -lQt6Gui
OPENSSL_LIBS = -lssl -lcrypto
QT_INCLUDES = -I/usr/include/qt6 -I/usr/include/qt6/QtCore -I/usr/include/qt6/QtWidgets -I/usr/include/qt6/QtGui
LDFLAGS = -fPIC

# Debug mode configuration
ifdef DEBUG
    CXXFLAGS += -g -DDEBUG -O0
    $(info DEBUG mode enabled - building with debug symbols and no optimization)
else
    CXXFLAGS += -O2
endif

# Verbose mode configuration
ifdef VERBOSE
    Q =
    $(info VERBOSE mode enabled - showing all commands)
else
    Q = @
endif

SRCDIR = src
INCDIR = include
BUILDDIR = build
OBJDIR = $(BUILDDIR)/obj
BINDIR = $(BUILDDIR)/bin

SOURCES = $(wildcard $(SRCDIR)/*.cpp)
HEADERS = $(wildcard $(INCDIR)/*.h)
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)
MOC_HEADERS = $(INCDIR)/main_window.h $(INCDIR)/settings_dialog.h
MOC_SOURCES = $(MOC_HEADERS:$(INCDIR)/%.h=$(OBJDIR)/moc_%.cpp)
MOC_OBJECTS = $(MOC_SOURCES:$(OBJDIR)/%.cpp=$(OBJDIR)/%.o)

TARGET = $(BINDIR)/password-manager

.PHONY: all clean install deps

all: $(TARGET)

# Create directories
$(OBJDIR):
	$(Q)mkdir -p $(OBJDIR)

$(BINDIR):
	$(Q)mkdir -p $(BINDIR)

# Generate MOC files
$(OBJDIR)/moc_%.cpp: $(INCDIR)/%.h | $(OBJDIR)
	@echo "MOC     $<"
	$(Q)$(MOC) $(QT_INCLUDES) $< -o $@

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	@echo "CXX     $<"
	$(Q)$(CXX) $(CXXFLAGS) $(QT_INCLUDES) -c $< -o $@

# Compile MOC files
$(OBJDIR)/moc_%.o: $(OBJDIR)/moc_%.cpp
	@echo "CXX     $<"
	$(Q)$(CXX) $(CXXFLAGS) $(QT_INCLUDES) -c $< -o $@

# Link executable
$(TARGET): $(OBJECTS) $(MOC_OBJECTS) | $(BINDIR)
	@echo "LINK    $@"
	$(Q)$(CXX) $(OBJECTS) $(MOC_OBJECTS) $(QT_LIBS) $(OPENSSL_LIBS) $(LDFLAGS) -o $@

# Install dependencies (Ubuntu/Debian)
deps:
	sudo apt update
	sudo apt install -y build-essential cmake qt6-base-dev qt6-tools-dev qt6-tools-dev-tools libssl-dev pkg-config

# Clean build files
clean:
	rm -rf $(BUILDDIR)

# Install the application
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/password-manager
	@echo "Password Manager installed to /usr/local/bin/password-manager"
	@echo "You can now run it with: password-manager"

# Uninstall the application
uninstall:
	sudo rm -f /usr/local/bin/password-manager
	@if [ -f "$(HOME)/.local/share/applications/password-manager.desktop" ]; then \
		rm -f "$(HOME)/.local/share/applications/password-manager.desktop"; \
		echo "Desktop entry removed from applications menu"; \
	fi
	@if command -v update-desktop-database >/dev/null 2>&1; then \
		update-desktop-database "$(HOME)/.local/share/applications/" 2>/dev/null || true; \
		echo "Applications menu updated"; \
	fi
	@echo "Password Manager uninstalled from /usr/local/bin/"
	@echo "Note: User data in ~/.local/share/PasswordManager/ and ~/.config/PasswordManager/ is preserved"

# Run the application
run: $(TARGET)
	./$(TARGET)

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)

# Help
help:
	@echo "Available targets:"
	@echo "  all       - Build the application"
	@echo "  deps      - Install dependencies (Ubuntu/Debian)"
	@echo "  clean     - Remove build files"
	@echo "  install   - Install to system (/usr/local/bin/)"
	@echo "  uninstall - Remove from system"
	@echo "  run       - Run the application"
	@echo "  debug     - Build with debug symbols"
	@echo "  help      - Show this help"
