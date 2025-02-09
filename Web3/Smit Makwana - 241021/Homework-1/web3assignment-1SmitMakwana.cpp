#include <iostream>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <unordered_map>

using namespace std;

// Function to compute SHA-256 hash
string sha256(const string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int main() {
    string P1, P2;
    int k;
    cin >> P1 >> P2 >> k;

    unordered_map<string, string> hashPrefixMap;
    string S1, S2;
    
    for (int i = 0; ; i++) {
        string candidate1 = P1 + to_string(i);
        string hash1 = sha256(candidate1).substr(0, k);
        
        if (hashPrefixMap.find(hash1) != hashPrefixMap.end()) {
            S1 = hashPrefixMap[hash1];
            S2 = candidate1;
            break;
        }
        hashPrefixMap[hash1] = candidate1;

        string candidate2 = P2 + to_string(i);
        string hash2 = sha256(candidate2).substr(0, k);
        
        if (hashPrefixMap.find(hash2) != hashPrefixMap.end()) {
            S1 = hashPrefixMap[hash2];
            S2 = candidate2;
            break;
        }
        hashPrefixMap[hash2] = candidate2;
    }

    cout << S1 << endl;
    cout << S2 << endl;
    return 0;
}