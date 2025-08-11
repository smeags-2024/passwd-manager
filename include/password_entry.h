#ifndef PASSWORD_ENTRY_H
#define PASSWORD_ENTRY_H

#include <string>
#include <ctime>

struct PasswordEntry {
    std::string id;
    std::string title;
    std::string username;
    std::string password;
    std::string url;
    std::string notes;
    std::time_t created;
    std::time_t modified;
    
    PasswordEntry() : created(std::time(nullptr)), modified(std::time(nullptr)) {}
    
    PasswordEntry(const std::string& title, const std::string& username, 
                 const std::string& password, const std::string& url = "",
                 const std::string& notes = "")
        : title(title), username(username), password(password), 
          url(url), notes(notes), created(std::time(nullptr)), modified(std::time(nullptr)) {
        generateId();
    }
    
    void generateId();
    std::string toString() const;
    static PasswordEntry fromString(const std::string& data);
};

#endif // PASSWORD_ENTRY_H
