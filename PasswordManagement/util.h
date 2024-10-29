#ifndef UTIL_H
#define UTIL_H

#include <string>

std::string trim(const std::string& str);
std::string getTrimmedInput(const std::string& prompt);
int getIntegerInput(const std::string& prompt);
std::string generateConfirmationCode(int length = 6);

#endif // UTIL_H
