extern "C" {
#include "ejudge/dyntrie.h"
}

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <print>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

std::vector<std::string> read_strings(const std::string &file)
{
    std::ifstream f(file);
    if (!f) throw std::runtime_error("cannot open file");
    std::vector<std::string> res;
    std::string buf;
    while (std::getline(f, buf)) {
        size_t e = buf.size();
        while (e > 0 && std::isspace(uint8_t(buf[e-1]))) --e;
        buf.erase(e);
        res.push_back(std::move(buf));
    }
    return res;
}

const unsigned char *as_puc(const char *s)
{
    return reinterpret_cast<const unsigned char *>(s);
}

void *as_pv(size_t v)
{
    return reinterpret_cast<void *>(static_cast<uintptr_t>(v));
}

void runonfile(const std::string &file)
{
    std::println("Testing on file {}", file);
    auto strs = read_strings(file);
    std::print("  direct order "); std::cout.flush();
    struct dyntrie_node *root = nullptr;
    for (size_t i = 0; i < strs.size(); ++i) {
        dyntrie_insert(&root, as_puc(strs[i].c_str()), as_pv(i + 1), 0, nullptr);
    }
    for (size_t i = 0; i < strs.size(); ++i) {
        auto ppv = dyntrie_get(&root, as_puc(strs[i].c_str()));
        if (ppv != as_pv(i + 1)) {
            std::println("String {} not found", strs[i]);
            abort();
        }
    }
    for (size_t i = 0; i < strs.size(); ++i) {
        dyntrie_remove(&root, as_puc(strs[i].c_str()), nullptr);
    }
    if (root != nullptr) {
        std::println("trie is not empty");
        abort();
    }
    std::println("ok");

    std::print("  reverse order "); std::cout.flush();
    root = nullptr;
    for (size_t i = strs.size(); i > 0; --i) {
        dyntrie_insert(&root, as_puc(strs[i-1].c_str()), as_pv(i), 0, nullptr);
    }
    for (size_t i = 0; i < strs.size(); ++i) {
        auto ppv = dyntrie_get(&root, as_puc(strs[i].c_str()));
        if (ppv != as_pv(i + 1)) {
            std::println("String {} not found", strs[i]);
            abort();
        }
    }
    for (size_t i = 0; i < strs.size(); ++i) {
        dyntrie_remove(&root, as_puc(strs[i].c_str()), nullptr);
    }
    if (root != nullptr) {
        std::println("trie is not empty");
        abort();
    }
    std::println("ok");

    std::print("  random order "); std::cout.flush();
    auto rstrs = strs;
    std::random_device rd;
    std::shuffle(rstrs.begin(), rstrs.end(), std::mt19937_64(rd()));
    root = nullptr;
    for (size_t i = 0; i < rstrs.size(); ++i) {
        dyntrie_insert(&root, as_puc(rstrs[i].c_str()), as_pv(i+1), 0, nullptr);
    }
    for (size_t i = 0; i < strs.size(); ++i) {
        auto ppv = dyntrie_get(&root, as_puc(rstrs[i].c_str()));
        if (ppv != as_pv(i + 1)) {
            std::println("String {} not found", rstrs[i]);
            abort();
        }
    }
    for (size_t i = 0; i < strs.size(); ++i) {
        dyntrie_remove(&root, as_puc(strs[i].c_str()), nullptr);
    }
    if (root != nullptr) {
        std::println("trie is not empty");
        abort();
    }
    std::println("ok");

    std::print("  random prefix "); std::cout.flush();
    std::mt19937_64 rnd(rd());
    root = nullptr;
    std::map<std::string, size_t> mm;
    for (size_t i = 0; i < rstrs.size(); ++i) {
        dyntrie_insert(&root, as_puc(strs[i].c_str()), as_pv(i+1), 0, nullptr);
        mm[strs[i]] = i + 1;
    }
    for (int i = 0; i < 10; ++i) {
        size_t ind = rnd() % strs.size();
        size_t len = strs[ind].size();
        for (size_t j = 1; j < len; ++j) {
            std::string s(strs[ind], 0, j);
            auto res = dyntrie_get(&root, as_puc(s.c_str()));
            if (mm[s]) {
                if (as_pv(mm[s]) != res) {
                    std::println("String {} not found", s);
                    abort();
                }
            } else {
                if (res) {
                    std::println("non-existing string found", s);
                    abort();
                }
            }
        }
    }
    for (size_t i = 0; i < strs.size(); ++i) {
        dyntrie_remove(&root, as_puc(strs[i].c_str()), nullptr);
    }
    std::println("ok");

    std::print("  random suffix "); std::cout.flush();
    root = nullptr;
    for (size_t i = 0; i < rstrs.size(); ++i) {
        dyntrie_insert(&root, as_puc(strs[i].c_str()), as_pv(i+1), 0, nullptr);
    }
    for (int i = 0; i < 10; ++i) {
        size_t ind = rnd() % strs.size();
        size_t len = strs[ind].size();
        std::string s = strs[ind];
        for (size_t j = 1; j < len; ++j) {
            s += "a";
            void *res = dyntrie_get(&root, as_puc(s.c_str()));
            if (mm[s]) {
                if (as_pv(mm[s]) != res) {
                    std::println("String {} not found", s);
                    abort();
                }
            } else {
                if (res) {
                    std::println("non-existing string found", s);
                    abort();
                }
            }
        }
    }
    for (size_t i = 0; i < strs.size(); ++i) {
        dyntrie_remove(&root, as_puc(strs[i].c_str()), nullptr);
    }
    std::println("ok");
}

int main(int argc, char *argv[])
{
    runonfile(std::string(argv[1]));
}
