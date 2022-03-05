#include <regex>
#include <vector>
#include <fstream>
#include <iostream>
#include <unistd.h>

#include "rev_hw.h"

std::string sanitize_string(const std::string &raw, bool revert_replace = false)
{
  const char *sanitize_list[5][2] = { // ENT_QUOTES | ENT_HTML5
                                      { "&", "&amp;" },
                                      { "\"", "&quot;" },
                                      { "'", "&apos;" },
                                      { "<", "&lt;" },
                                      { ">", "&gt;" }
  };

  std::string str = raw;

  if (revert_replace) {
    // Set position '&amp;' to begin or end ..
    constexpr auto end = sizeof(sanitize_list) / sizeof(sanitize_list[0]);
    std::reverse(sanitize_list, sanitize_list + end);
  }

  for (auto &ent : sanitize_list) {

    auto found_from = revert_replace ? ent[1] : ent[0];
    auto replace_to = revert_replace ? ent[0] : ent[1];

    str = std::regex_replace(str, std::regex(found_from), replace_to);
  }

  return str;
}

std::string encrypt_password(char pass_format, const std::string &pwd)
{
  std::string pass_enc;

  switch (pass_format) {
    case '1':
      rev_HW_AES_AesEncrypt(pwd.data(), pwd.size(), pass_enc);
      break;
    case '2':
      rev_HW_AES_AesCBCEncrypt(pwd.data(), pwd.size(), pass_enc);
      break;
  }

  rev_HW_AES_AscVisible(reinterpret_cast<uint8_t *>(&pass_enc[0]), pass_enc.size());

  pass_enc.insert(0, { '$', pass_format });
  pass_enc.push_back('$');

  return pass_enc;
}

std::string decrypt_password(const std::string &pwd)
{
  std::string pass_dec;
  std::string pass_enc(pwd.begin() + 2, pwd.end() - 1);

  rev_HW_AES_AscUnvisible(reinterpret_cast<uint8_t *>(&pass_enc[0]), pass_enc.size());

  switch (pwd.at(1)) {
    case '1':
      rev_HW_AES_AesDecrypt(pass_enc.data(), pass_enc.size(), pass_dec);
      break;
    case '2':
      rev_HW_AES_AesCBCDecrypt(pass_enc.data(), pass_enc.size(), pass_dec);
      break;
  }

  return pass_dec;
}

int main(int argc, char *argv[])
{
  auto usage_print = [&]() {
    std::cerr << "Usage: " << argv[0] << " [-e [-f]] [-d] [-s] <file or - (STDIN)>"
              << std::endl;

    std::cerr << " -e Encrypt raw password" << std::endl
              << " -d Decrypt sanitized password" << std::endl
              << " -s Print sanitized password" << std::endl
              << " -f Format password($1pwd$, $2pwd$). Example: -f 2" << std::endl;

    std::exit(EXIT_FAILURE);
  };

  char pwd_format      = 0;
  const char *pwd_file = "-";

  bool print_sanitize = false;
  bool fenc = false, fdec = false;

  int opt;
  while ((opt = getopt(argc, argv, "ef:ds")) != -1) {
    switch (opt) {
      case 'e':
        fenc = true;
        break;
      case 'f':
        pwd_format = *optarg;
        break;
      case 'd':
        fdec = true;
        break;
      case 's':
        print_sanitize = true;
        break;
    }
  }

  if ((fenc & fdec) | (!fenc & !fdec) | (fenc & (pwd_format == 0)) |
      (fdec & (pwd_format != 0))) {
    usage_print();
  }

  if (optind < argc) {
    pwd_file = argv[optind];
  }

  try {

    std::string pwd_str;

    std::ifstream file;
    std::istream &in = std::cin;

    if (*pwd_file != '-') {

      file.open(pwd_file);

      if (!file.is_open()) {
        std::cerr << "[-] File cannot open: " << pwd_file << std::endl;
        return 1;
      }

      in.rdbuf(file.rdbuf());
    }

    if (fdec) {

      while (std::getline(in, pwd_str)) {

        if (pwd_str.size() < 23 || (pwd_str[1] != '1' && pwd_str[1] != '2')) {
          std::cout << "[*] Skip. Error format password. " << pwd_str << std::endl;
          continue;
        }

        auto enc_pass = sanitize_string(pwd_str, true); // revert sanitize
        auto dec_pass = decrypt_password(enc_pass);

        if (print_sanitize) {
          enc_pass.swap(pwd_str);
        }

        std::cout << "[+] " << enc_pass << ':' << dec_pass << std::endl;
      }

    } else {

      if (pwd_format != '1' && pwd_format != '2') {
        std::cerr << "[-] Format password error '" << pwd_format << '\'' << std::endl;
        usage_print();
      }

      while (std::getline(in, pwd_str)) {

        if (pwd_str.empty()) {
          std::cout << "[*] Skip. pass.size() == 0" << std::endl;
          continue;
        }

        auto enc_pass = encrypt_password(pwd_format, pwd_str);

        if (print_sanitize) {
          enc_pass = sanitize_string(enc_pass);
        }

        std::cout << "[+] " << pwd_str << ':' << enc_pass << std::endl;
      }
    }
  } catch (const std::exception &e) {
    std::cerr << "[-] Error. " << e.what() << std::endl;
  }

  return 0;
}
