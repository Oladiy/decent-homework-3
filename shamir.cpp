#include <bitset>
#include "boost/algorithm/hex.hpp"
#include "cryptopp/ida.h"
#include "cryptopp/osrng.h"
#include "cryptopp/files.h"
#include <iostream>

namespace Shamir {
    int min_threshold = 2;
    int max_threshold = 100;
    int base_hex = 16;
    int channel_size = 4;
    int hex_rank = 2;
}

using std::cin;
using std::cout;
using std::endl;
using std::string;
using std::vector;

int split() {
    string secret;
    int shares_number;
    int threshold;
    cin >> secret;
    cin >> shares_number >> threshold;

    if (shares_number < Shamir::min_threshold || shares_number < threshold || shares_number > Shamir::max_threshold) {
        return EXIT_FAILURE;
    }
    if (threshold < Shamir::min_threshold || threshold > Shamir::max_threshold || threshold > shares_number) {
        return EXIT_FAILURE;
    }

    // подготавливаем параметры для разделения секрета
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::ChannelSwitch *channelSwitch;
    CryptoPP::ArraySource source(secret, false,
                       new CryptoPP::SecretSharing(rng, threshold, shares_number, channelSwitch = new CryptoPP::ChannelSwitch));
    vector<std::ostringstream> shares(shares_number);
    CryptoPP::vector_member_ptrs<CryptoPP::FileSink> sinks(shares_number);
    string channel;
    // начинаем делить секрет на куски, складываем их в бинарном виде в shares
    for (int i = 0; i < shares_number; i++) {
        sinks[i].reset(new CryptoPP::FileSink(shares[i]));
        channel = CryptoPP::WordToString<CryptoPP::word32>(i);
        sinks[i]->Put((CryptoPP::byte*)channel.data(), Shamir::channel_size);
        channelSwitch->AddRoute(channel, *sinks[i], CryptoPP::DEFAULT_CHANNEL);
    }
    source.PumpAll();

    // конвертируем байтовую строку кусочка секрета в hex-формат и выводим ее в stdout
    for (const auto& share : shares) {
        string share_byte = share.str();
        string share_hex;
        boost::algorithm::hex(share_byte.begin(), share_byte.end(), std::back_inserter(share_hex));
        cout << share_hex << endl;
    }
    cout << endl;

    return EXIT_SUCCESS;
}

vector<char> hex_to_bytes(const string& hex) {
    vector<char> bytes;

    for (unsigned int i = 0; i < hex.length(); i += Shamir::hex_rank) {
        string byte_string = hex.substr(i, Shamir::hex_rank);
        char byte = (char) strtol(byte_string.c_str(), nullptr, Shamir::base_hex);
        bytes.push_back(byte);
    }

    return bytes;
}

int recover() {
    vector<string> shares_hex;
    string secret_part;
    while (cin >> secret_part) {
        shares_hex.push_back(secret_part);
    }

    int threshold = shares_hex.size();

    // конвертируем каждый кусочек секрета из hex-формата в двоичный
    vector<string> shares_byte(threshold);
    int i = 0;
    for (auto& share : shares_hex) {
        vector<char> share_byte = hex_to_bytes(share);
        for (auto& byte : share_byte) {
            shares_byte[i] += byte;
        }
        i++;
    }

    // начинаем покусочно восстанавливать секрет, складывая результат в out
    std::ostringstream out;
    CryptoPP::SecretRecovery recovery(threshold, new CryptoPP::FileSink(out));

    CryptoPP::SecByteBlock channel(Shamir::channel_size);
    for (i = 0; i < threshold; i++) {
        CryptoPP::ArraySource arraySource(shares_byte[i], false);
        arraySource.Pump(Shamir::channel_size);
        arraySource.Get(channel, Shamir::channel_size);
        arraySource.Attach(new CryptoPP::ChannelSwitch(recovery, string((char*)channel.begin(), Shamir::channel_size)));
        arraySource.PumpAll();
    }

    const auto& secret = out.str();
    cout << endl << secret << endl;

    return EXIT_SUCCESS;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        return EXIT_FAILURE;
    }

    string argument = argv[1];
    if (argument == "split") {
        int status_code = split();
        if (status_code == EXIT_SUCCESS) {
            cout << "Secret was successfully shared." << endl;
        }
    } else if (argument == "recover") {
        int status_code = recover();
        if (status_code == EXIT_SUCCESS) {
            cout << "Secret was successfully recovered." << endl;
        }
    } else {
        EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
