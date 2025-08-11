# Password Manager - Quick Start Guide

## 🚀 Installation & First Run

### 1. Quick Install (Automated)
```bash
cd passwd-manager
./build.sh
```

### 2. Manual Install
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install build-essential cmake qt6-base-dev qt6-tools-dev libssl-dev pkg-config

# Build
make all

# Run
./build/bin/password-manager
```

## 📋 Basic Usage

### First Time Setup
1. **Launch** the application
2. **File → New Database** (creates `data/passwords.db`)
3. **Set master password** (minimum 6 characters)
4. **Start adding entries**

### Adding Your First Password
1. Click **"Add"** button
2. Fill in:
   - **Title**: "Gmail Account" 
   - **Username**: "your.email@gmail.com"
   - **Password**: Click **"Generate"** for secure password
   - **URL**: "https://gmail.com"
3. Click **"Save"**

### Essential Features
- **Search**: Type in search box to filter entries
- **Copy**: Use "Copy Username" and "Copy Password" buttons  
- **Edit**: Select entry → "Edit" → modify → "Save"
- **Generate**: Always use "Generate" for new passwords

## ⚙️ Settings (File → Settings)

### Security Settings
- **Auto-lock**: Enable timeout protection
- **Password length**: Set minimum requirements
- **Encryption**: Use AES-256 (recommended)

### Theme & Interface  
- **Theme**: Choose System/Dark/Light
- **Password strength**: Enable indicator
- **Remember database**: Auto-open last database

## 🔒 Security Best Practices

### Master Password
- **Length**: 12+ characters recommended
- **Complexity**: Mix letters, numbers, symbols
- **Uniqueness**: Don't reuse elsewhere
- **Memorable**: Use passphrase technique

### Generated Passwords
- **Always generate**: Don't create manually
- **Unique per site**: Never reuse passwords
- **Regular updates**: Change important passwords periodically

### Database Safety
- **Backup regularly**: Copy `passwords.db` safely
- **Secure location**: Don't store in cloud unencrypted
- **Access control**: Protect your computer with screen lock

## 🛟 Troubleshooting

### Build Issues
```bash
# Try automated fix
./build.sh --install-deps

# Or check specific issues
make deps  # Install dependencies
make clean # Clean build files
```

### Application Issues
- **Won't start**: Check Qt6 runtime libraries
- **Can't open database**: Verify master password
- **Slow performance**: Large databases take time to decrypt

### Getting Help
- **Check logs**: `logs/password-manager.log`
- **Review README**: Full documentation available
- **Verify installation**: Ensure all dependencies installed

## 📁 File Locations

```
Project Structure:
├── data/passwords.db           # Your encrypted database
├── build/bin/password-manager  # Executable
├── logs/password-manager.log   # Application logs
└── ~/.config/PasswordManager/  # Settings (Linux)
```

## 🔧 Quick Commands

```bash
# Build and run
make all && make run

# Development build  
make debug

# Clean build
make clean && make all

# Install dependencies
make deps

# Check executable
./build/bin/password-manager --version
```

## 🎯 Next Steps

1. **Import existing passwords** from browsers/other managers
2. **Configure auto-lock** for shared computers  
3. **Set up backups** of your database file
4. **Customize theme** and preferences
5. **Generate strong passwords** for all accounts

---

**Need Help?** Check the full README.md for comprehensive documentation.
