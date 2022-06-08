/* -*- mode: c++; c-basic-offset: 4 -*- */

#include <string>
#include <vector>
#include <iostream>
#include <algorithm>

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

namespace
{

std::string program_name;

auto
is_suffix(const std::string &str, const std::string &suffix)
{
    return str.size() >= suffix.size()
        && !str.compare(str.size() - suffix.size(), suffix.size(), suffix);
}

auto
is_prefix(const std::string &str, const std::string &prefix)
{
    return str.size() >= prefix.size()
        && !str.compare(0, prefix.size(), prefix);
}
    
auto
collect_files(const std::string &directory)
{
    std::vector<std::string> res;

    DIR *d = opendir(directory.c_str());
    if (!d) {
        std::cerr << program_name << ": cannot open " << directory << ": " << strerror(errno) << std::endl;
        exit(1);
    }

    struct dirent *dd;
    while ((dd = readdir(d))) {
        std::string n{dd->d_name};
        if (n.size() > 0 && n[0] != '.') {
            res.push_back(std::move(n));
        }
    }

    closedir(d); d = NULL;

    std::sort(res.begin(), res.end());

    return res;
}
    
void
process(
        const std::vector<std::string> &files,
        const std::string &suffix,
        const std::string &name)
{
    // candidates: name "." num "." suffix
    std::vector<int> nums;

    for (const auto &s : files) {
        if (is_prefix(s, name) && is_suffix(s, suffix) && s.size() > name.size() + suffix.size() + 2 && s[name.size()] == '.' && s[s.size() - suffix.size() - 1] == '.') {
            std::string ss(s, name.size() + 1, s.size() - name.size() - suffix.size() - 2);

            int val = -1;
            try {
                size_t endpos = 0;
                val = std::stoi(ss, &endpos);
                if (endpos != ss.size()) {
                    val = -1;
                }
            } catch (...) {
            }
            if (val > 0) {
                nums.push_back(val);
            }
        }
    }
    std::sort(nums.begin(), nums.end(), std::greater());

    for (int serial : nums) {
        std::string n1 = name + "." + std::to_string(serial) + "." + suffix;
        std::string n2 = name + "." + std::to_string(serial + 1) + "." + suffix;
        std::cout << "mv " << n1 << " " << n2 << std::endl;
    }
    std::cout << "cp -p " << name << " " << name << ".1" << std::endl;
    std::cout << "> " << name << std::endl;
}

}

int
main(int argc, char *argv[])
{
    if (argc < 3) {
        std::cerr << "wrong number of arguments" << std::endl;
    }

    program_name = argv[0];
    auto files = collect_files(argv[1]);
    std::string suffix{argv[2]};

    for (int i = 3; i < argc; ++i) {
        process(files, suffix, argv[i]);
    }
}
