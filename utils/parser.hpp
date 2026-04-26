#include <string>
#include <vector>
class Parser {
  public:
  std::vector<char> flags;
  void extract_flags(std::string command);
};
