#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>

class Encryption {
public:
	static std::string encrypt(const std::string& plaintext, const std::string& key);
	static std::string decrypt(const std::string& ciphertext, const std::string& key);

};

#endif // ENCRYPTION_H