#include "Encryption.h"

std::string decryptConfiguration() {
	/*
	* - could work, but doesn't at the moment (the key should be derived from the MD5 of an obfuscation string)
	*
	std::string md5_string_of_uuid = md5("c588eecb-1724-4ed1-a5df-d23ec7d76f44");
	//std::string first_16_chars = md5_string_of_uuid.substr(0, 16);
	std::vector<unsigned char> key{ md5_string_of_uuid.begin(), md5_string_of_uuid.end() };
	*/

	// AES IV - Hex formatted random IV
	const unsigned char iv[16] = { 0xc1, 0x2a, 0x0f, 0x50, 0x34, 0xf0, 0xbb, 0x02, 0x7b, 0x9b, 0xb6, 0x1c, 0xe1, 0xad, 0x60, 0xc2 };
	// AES Key - MD5 hash of a random UUID string
	const std::vector<unsigned char> key = { 0x02, 0x4d, 0x46, 0xaa, 0xd4, 0x5c, 0x52, 0x4a, 0x94, 0x78, 0xa9, 0x0e, 0x26, 0xab, 0xf9, 0x57 };
	// AES Ciphertext - Encrypted configuration data
	std::vector<unsigned char> encrypted_config = { 0x58, 0x41, 0x1c, 0x42, 0x02, 0x5b, 0xf1, 0x8c, 0x12, 0x3e, 0x4f, 0x9e, 0xfc, 0x54, 0x1d, 0x2d };

	unsigned long padded_size = 0;
	std::vector<unsigned char> decrypted(encrypted_config.size());

	plusaes::decrypt_cbc(&encrypted_config[0], encrypted_config.size(), &key[0], key.size(), &iv, &decrypted[0], decrypted.size(), &padded_size);

	std::string config_data = reinterpret_cast<char const*>(&decrypted[0]);
	return config_data;
}

std::vector<std::string> Encrypt::parseConfiguration(std::string decrypted_config)
{
	std::string delim = ":";
	std::vector<std::string> config_entries{};

	size_t position = 0;
	while ((position = decrypted_config.find(delim)) != std::string::npos)
	{
		config_entries.push_back(decrypted_config.substr(0, position));
		config_entries.push_back(decrypted_config.substr(config_entries[0].size() + 1, position));
		decrypted_config.erase(0, position + delim.length());
	}

	return config_entries;
}

std::vector<std::string> Encrypt::returnConfigValues()
{
	std::string decrypted_config = decryptConfiguration();
	std::vector<std::string> decrypted_config_vec = parseConfiguration(decrypted_config);

	return decrypted_config_vec;
}

// this function works, but server-side padding is conflicts with this AES library
// - function is not used at the moment
std::vector<unsigned char> Encrypt::encryptNetworkTraffic(std::string data_to_encrypt)
{
	// AES IV - Hex formatted random IV
	const unsigned char iv[16] = { 0xc2, 0xa5, 0x5e, 0x98, 0x8b, 0x04, 0x2c, 0xd9, 0x62, 0xc1, 0xf1, 0x8b, 0x78, 0x53, 0x83, 0x15 };
	// AES Key - MD5 hash of a random UUID string
	const std::vector<unsigned char> key = { 0xb0, 0xef, 0x0d, 0xb4, 0xaf, 0xc2, 0xa3, 0x88, 0xe7, 0xfd, 0x4c, 0x40, 0xf1, 0xc9, 0x0b, 0x07 };

	const unsigned long encrypted_size = plusaes::get_padded_encrypted_size(data_to_encrypt.size());
	std::vector<unsigned char> encrypted(encrypted_size);

	plusaes::encrypt_cbc((unsigned char*)data_to_encrypt.data(), data_to_encrypt.size(), &key[0], key.size(), &iv, &encrypted[0], encrypted.size(), true);

	return encrypted;
}