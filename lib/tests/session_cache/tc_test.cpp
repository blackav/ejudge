#include "ejudge/session_cache.h"

#include <iostream>
#include <random>
#include <cstdint>
#include <set>
#include <vector>
#include <algorithm>
#include <map>
#include <unordered_map>
#include <chrono>
#include <cstring>

using namespace std;

struct Token
{
	static constexpr size_t SIZE = 32;
	unsigned char token[SIZE];

	void rnd(mt19937_64 &r)
	{
		uint64_t *u64 = reinterpret_cast<uint64_t *>(token);
		u64[0] = r();
		u64[1] = r();
		u64[2] = r();
		u64[3] = r();
	}

	friend bool operator < (const Token &t1, const Token &t2)
	{
		return memcmp(t1.token, t2.token, Token::SIZE) < 0;
	}
	friend bool operator <= (const Token &t1, const Token &t2)
	{
		return memcmp(t1.token, t2.token, Token::SIZE) <= 0;
	}
	friend bool operator > (const Token &t1, const Token &t2)
	{
		return memcmp(t1.token, t2.token, Token::SIZE) > 0;
	}
	friend bool operator >= (const Token &t1, const Token &t2)
	{
		return memcmp(t1.token, t2.token, Token::SIZE) >= 0;
	}
	friend bool operator == (const Token &t1, const Token &t2)
	{
		return memcmp(t1.token, t2.token, Token::SIZE) == 0;
	}
	friend bool operator != (const Token &t1, const Token &t2)
	{
		return memcmp(t1.token, t2.token, Token::SIZE) != 0;
	}
};

template<>
struct std::hash<Token>
{
	size_t operator() (const Token &t) const noexcept
	{
		const uint64_t *u64 = reinterpret_cast<const uint64_t *>(t.token);
		return u64[0] ^ u64[1] ^ u64[2] ^ u64[3];
	}
};

int main(int argc, char *argv[])
{
	using std::chrono::high_resolution_clock;
	using std::chrono::duration_cast;
	using std::chrono::microseconds;

	uint64_t seed = stoull(argv[1], NULL, 10);
	mt19937_64 rnd(seed);

	int valcount = stol(argv[2], NULL, 10);
	[[maybe_unused]]
	int nonvalcount = stol(argv[3], NULL, 10);
	[[maybe_unused]]
	int hitcount = stol(argv[4], NULL, 10);
	[[maybe_unused]]
	int misscount = stol(argv[5], NULL, 10);

	cout << "generating keys..." << endl;
	auto c1 = high_resolution_clock::now();
	set<Token> tokset;
	for (int i = 0; i < valcount; ++i) {
		Token t;
		t.rnd(rnd);
		while (tokset.count(t) > 0) {
			t.rnd(rnd);
		}
		tokset.insert(t);
	}
	auto c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	cout << "generating non-keys..." << endl;
	c1 = high_resolution_clock::now();
	set<Token> ntokset;
	for (int i = 0; i < nonvalcount; ++i) {
		Token t;
		t.rnd(rnd);
		while (tokset.count(t) > 0 || ntokset.count(t) > 0) {
			t.rnd(rnd);
		}
		ntokset.insert(t);
	}
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	cout << "preparing sequences..." << endl;
	c1 = high_resolution_clock::now();
	vector<Token> tokvec(tokset.begin(), tokset.end());
	vector<Token> tokshuf(tokvec);
	shuffle(tokshuf.begin(), tokshuf.end(), rnd);
	vector<Token> ntokvec(ntokset.begin(), ntokset.end());
	vector<pair<Token, bool>> queries(hitcount + misscount);
	int ii = 0;
	for (int i = 0; i < hitcount; ++i) {
		queries[ii++] = { tokvec[rnd() % valcount], true };
	}
	for (int i = 0; i < misscount; ++i) {
		queries[ii++] = { ntokvec[rnd() % nonvalcount], false };
	}
	shuffle(queries.begin(), queries.end(), rnd);
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	struct id_cache idc;
	idc_init(&idc);

	cout << "inserting..." << endl;
	c1 = high_resolution_clock::now();
	for (int i = 0; i < valcount; ++i) {
		tc_insert(&idc.t, tokshuf[i].token);
	}
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	cout << "searching..." << endl;
	c1 = high_resolution_clock::now();
	for (const auto &p : queries) {
		auto res = tc_find(&idc.t, p.first.token);
		if ((res != nullptr) != p.second) abort();
	}
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	cout << "removing..." << endl;
	c1 = high_resolution_clock::now();
	for (int i = 0; i < valcount; ++i) {
		auto res = tc_remove(&idc.t, tokshuf[i].token, nullptr);
		if (!res) abort();
		auto ptr = tc_find(&idc.t, tokshuf[i].token);
		if (ptr) abort();
	}
	if (idc.s.used != 0) abort();
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	// check for all zeroes
	size_t memsz = idc.t.used * sizeof(idc.t.info[0]);
	const unsigned char *ptr = reinterpret_cast<const unsigned char *>(idc.t.info);
	for (size_t jj = 0; jj < memsz; ++jj)
		if (ptr[jj])
			abort();

	return 0;

#if 0
	// compare with std::map
	cout << "inserting into std::map..." << endl;
	c1 = high_resolution_clock::now();
	std::map<session_t, struct new_session_info> mm; 
	for (int i = 0; i < valcount; ++i) {
		struct new_session_info nsi{};
		mm.insert({ keyshuf[i], nsi});
	}
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	cout << "searching in std::map..." << endl;
	c1 = high_resolution_clock::now();
	for (const auto &p : queries) {
		auto it = mm.find(p.first);
		if ((it != mm.end()) != p.second) abort();
	}
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	// compare with std::unordered_map
	cout << "inserting into std::unordered_map..." << endl;
	c1 = high_resolution_clock::now();
	std::unordered_map<session_t, struct new_session_info> um; 
	for (int i = 0; i < valcount; ++i) {
		struct new_session_info nsi{};
		um.insert({ keyshuf[i], nsi});
	}
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	cout << "searching in std::unordered_map..." << endl;
	c1 = high_resolution_clock::now();
	for (const auto &p : queries) {
		auto it = um.find(p.first);
		if ((it != um.end()) != p.second) abort();
	}
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;
#endif
}
