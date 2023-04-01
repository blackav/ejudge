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

using namespace std;

using session_t = pair<uint64_t, uint64_t>;

template<>
struct std::hash<session_t>
{
	size_t operator()(const session_t &ss) const noexcept
	{
		return ss.first ^ ss.second;
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
	int nonvalcount = stol(argv[3], NULL, 10);
	int hitcount = stol(argv[4], NULL, 10);
	int misscount = stol(argv[5], NULL, 10);

	cout << "generating keys..." << endl;
	auto c1 = high_resolution_clock::now();
	set<session_t> keyset;
	for (int i = 0; i < valcount; ++i) {
		session_t s;
		s.first = rnd(); s.second = rnd();	
		while (keyset.count(s) > 0) {
			s.first = rnd(); s.second = rnd();
		}
		keyset.insert(s);
	}
	auto c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	cout << "generating non-keys..." << endl;
	c1 = high_resolution_clock::now();
	set<session_t> nkeyset;
	for (int i = 0; i < nonvalcount; ++i) {
		session_t s;
		s.first = rnd(); s.second = rnd();
		while (keyset.count(s) > 0 || nkeyset.count(s) > 0) {
			s.first = rnd(); s.second = rnd();
		}
		nkeyset.insert(s);
	}
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	cout << "preparing sequences..." << endl;
	c1 = high_resolution_clock::now();
	vector<session_t> keyvec(keyset.begin(), keyset.end());
	vector<session_t> keyshuf(keyvec);
	shuffle(keyshuf.begin(), keyshuf.end(), rnd);
	vector<session_t> nkeyvec(nkeyset.begin(), nkeyset.end());
	vector<pair<session_t, bool>> queries(hitcount + misscount);
	int ii = 0;
	for (int i = 0; i < hitcount; ++i) {
		queries[ii++] = { keyvec[rnd() % valcount], true };
	}
	for (int i = 0; i < misscount; ++i) {
		queries[ii++] = { nkeyvec[rnd() % nonvalcount], false };
	}
	shuffle(queries.begin(), queries.end(), rnd);
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	struct id_cache idc;
	idc_init(&idc);

	cout << "inserting..." << endl;
	c1 = high_resolution_clock::now();
	for (int i = 0; i < valcount; ++i) {
		nsc_insert(&idc.s, keyshuf[i].first, keyshuf[i].second);
	}
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	cout << "searching..." << endl;
	c1 = high_resolution_clock::now();
	for (const auto &p : queries) {
		auto res = nsc_find(&idc.s, p.first.first, p.first.second);
		if ((res != nullptr) != p.second) abort();
	}
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	cout << "removing..." << endl;
	c1 = high_resolution_clock::now();
	for (int i = 0; i < valcount; ++i) {
		auto res = nsc_remove(&idc.s, keyshuf[i].first, keyshuf[i].second, nullptr);
		if (!res) abort();
		auto ptr = nsc_find(&idc.s, keyshuf[i].first, keyshuf[i].second);
		if (ptr) abort();
	}
	if (idc.s.used != 0) abort();
	c2 = high_resolution_clock::now();
	cout << "done in " << duration_cast<microseconds>(c2 - c1).count() << " us" << endl;

	// check for all zeroes
	size_t memsz = idc.s.used * sizeof(idc.s.info[0]);
	const unsigned char *ptr = reinterpret_cast<const unsigned char *>(idc.s.info);
	for (size_t jj = 0; jj < memsz; ++jj)
		if (ptr[jj])
			abort();

	return 0;

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
}
