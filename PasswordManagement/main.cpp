#include <iostream>
#include "encryption.h"

int main() {
	std::string key = "examplekey734567";
	std::string plaintext = "SecretPassword";

	std::string encrypted = Encryption::encrypt(plaintext, key);
	std::string decrypted = Encryption::decrypt(encrypted, key);

	std::cout << "Plaintext: " << plaintext << std::endl;
	std::cout << "Encrypted: " << encrypted << std::endl;
	std::cout << "Decrypted: " << decrypted << std::endl;

	return 0;

}