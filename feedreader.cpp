#include <stdio.h>
#include <string>
#include <string.h>
#include <cstring>
#include <stdlib.h>
#include <ctype.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <unistd.h> // socket close
#include <netinet/in.h> //sockaddr_in
#include <arpa/inet.h> //aton ntoa
#include <sys/time.h> // timeout
#include <netdb.h> // gethostbyname


#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"


// https://stackoverflow.com/questions/17685466/http-request-by-sockets-in-c

/** Naètìní a uchování informací pøedaných
 * v parametrech.
 */
class Argparser {
private:
	int argerrcode = 1; // navratovy kod pri chybe v argumentech
	// obsazeni parametru
	bool isServer; // Server parametr nalezen
public:
	bool isFeedfile; // Timeout parametr nalezen
	bool isURL; // Type parametr nalezen
	bool isCertfile; // Name parametr nalezen
	bool isCertaddr; // Iterativni parametr nalezen
	bool isTimestamp; // Iterativni parametr nalezen
	bool isAuthor; // Iterativni parametr nalezen
	bool isURLasoc; // Iterativni parametr nalezen
	bool isDebugging; // Iterativni parametr nalezen
	// data parametru
	std::string strFeedfile; // Server parametr data
	std::string strURL; // Type parametr data
	std::string strCertfile; // Name parametr data
	std::string strCertaddr; // Name parametr data

	Argparser() {
		this->init_arguments();
	}

	Argparser(int argc, char **argv) {
		this->init_arguments();
		this->parse_arguments(argc, argv);
	}

	void init_arguments() {
		isFeedfile = false;
		isURL = false;
		isCertfile = false;
		isCertaddr = false;
		isTimestamp = false;
		isAuthor = false;
		isURLasoc = false;
		isDebugging = false;
		strFeedfile = "A";
		strURL = "A";
		strCertfile = "";
		strCertaddr = "";
	}

	/** Projde argumenty a nastaví dle nich hodnoty instance
	 */
	bool parse_arguments(int argc, char **argv) {
		for (int i = 1; i < argc; i++) {
			if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
				std::cout << "Napoveda k programu:\n";
				std::cout << "\tNastroj stahuje data ze zadanych zdroju ve formatu Atom a RSS\n";
				std::cout << "Podporované parametry:\n";
				std::cout << "\t-f <feedfile>: soubor s url adresami ke stazeni, komentare lze psat s #:\n";
				std::cout << "\t-c <certfile>: soubor s certifikaty pro overeni platnosti\n";
				std::cout << "\t-C <certaddr>: adresar, ve kterem se maji vyhledat certifikaty pro overeni platnosti\n";
				std::cout << "\t-T vypise u zaznamu cas posledni zmeny\n";
				std::cout << "\t-u: vypise u zaznamu url\n";
				std::cout << "\t-a: vypise u zaznamu autora\n";
				std::cout << "\t--debugging: enable verbose debug output\n";
				std::cout << "\turl: adresa zdroje\n";
				exit(0);
			}
			else if (!strcmp(argv[i], "-f") && !isFeedfile) {
				isFeedfile = true;
				i++;
				if (i < argc) {
					strFeedfile = argv[i];
					continue;
				}
			}
			else if (!strcmp(argv[i], "-c") && !isCertfile) {
				isCertfile = true;
				i++;
				if (i < argc) {
					strCertfile = argv[i];
					continue;
				}
			}
			else if (!strcmp(argv[i], "-C") && !isCertaddr) {
				isCertaddr = true;
				i++;
				if (i < argc) {
					strCertaddr = argv[i];
					continue;
				}
			}
			else if (!strcmp(argv[i], "-T") && !isTimestamp) {
				isTimestamp = true;
				continue;
			}
			else if (!strcmp(argv[i], "-u") && !isURLasoc) {
				isURLasoc = true;
				continue;
			}
			else if (!strcmp(argv[i], "-a") && !isAuthor) {
				isAuthor = true;
				continue;
			}
			else if (!strcmp(argv[i], "--debugging") && !isDebugging) {
				isDebugging = true;
				continue;
			}
			else if (!isURL) {
				isURL = true;
				strURL = argv[i];
				continue;
			}
			std::cerr << "Spatne zadane parametry." << std::endl;
			exit(argerrcode);
		}
		if (isURL == isFeedfile) {
			std::cerr << "Spatne zadane parametry." << std::endl;
			exit(argerrcode);
		}
		/*if (strCertaddr == "") {
			strCertaddr = NULL;
		}
		if (strCertfile == "") {
			strCertfile = "/etc/ssl/certs";
			strCertfile = NULL;
		}*/
		return true;
	}
};


class Feed {
private:
	Argparser arg;
	std::string request; // Name parametr data
	std::string response; // Not parsed response from server

	int port_number;
	BIO * bio;
	SSL_CTX * ctx; // = SSL_CTX_new(SSLv23_client_method());
	SSL * ssl;

public:
	std::string url_adress; // Name parametr data
	int return_code;
	/**
	 * @brief Vytvori objekt klienta, potrebuje mit pristup k parametrum
	 * @param argp parametry po spusteni aplikace
	 */
	Feed(Argparser argp, std::string adress) {
		return_code = 0;
		url_adress = adress;
		std::string https = "https://";
		std::string http = "http://";
		if (strncmp(url_adress.c_str(), https.c_str(), https.size()) == 0) {
			port_number = 443;
			url_adress.erase(0, https.size());
		}
		else if (strncmp(url_adress.c_str(), http.c_str(), http.size()) == 0) {
			port_number = 80;
			url_adress.erase(0, http.size());
		}
		else {
			raise_error("Error Invalid URL adress.");
		}
		request = "/" + str_after(url_adress, "/", true);
		url_adress = str_before(url_adress, "/", true);
		debug("url_adress: " + url_adress);
		debug("port_number: " + port_number);
		debug("request: " + request);
		arg = argp;
	}

	/**
	 * @brief Pripravi dotaz, odesle ho, prijme odpoved, analyzuje ji
	 * @return 0 pri uspechu
	 */
	void run() {
		try {
			if (port_number == 80) {
				run_80();
			}
			else {
				run_443();
			}
			get_response_from_server();
		}
		catch (int a) {

		}
	}

	/**
	 * @brief Pripravi dotaz, odesle ho, prijme odpoved, analyzuje ji
	 * @return 0 pri uspechu
	 */
	void run_80() {
		std::string addr_req = url_adress + ":80";
		bio = BIO_new_connect(addr_req.c_str());
		if (bio == NULL){
			raise_error("Error BIO_new_connect.");
		}
		if (BIO_do_connect(bio) <= 0){
			raise_error("Error BIO_do_connect.");
		}
		std::stringstream ss;
		ss << "POST " << request << " HTTP/1.1\r\n"
			<< "Host: " << url_adress << "\r\n"
			<< "Accept: */*\r\n"
			<< "Connection: close\r\n"
			<< "\r\n\r\n";
		std::string request = ss.str();
		if (BIO_write(bio, request.c_str(), request.length()) <= 0)	{
			raise_error("Error BIO_write.");
		}
	}

	/**
	 * @brief Pripravi dotaz, odesle ho, prijme odpoved, analyzuje ji
	 * @return 0 pri uspechu
	 */
	void run_443() {
		ctx = SSL_CTX_new(SSLv23_client_method());
		// SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
		SSL_CTX_set_verify_depth(ctx, 4);
		const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
		SSL_CTX_set_options(ctx, flags);
		if (!arg.strCertfile.empty()) {
			if (!SSL_CTX_load_verify_locations(ctx, arg.strCertfile.c_str(), NULL))	{
				if (!arg.strCertaddr.empty()) {
					if (!SSL_CTX_load_verify_locations(ctx, NULL, arg.strCertaddr.c_str())) {
						raise_error("Error SSL_CTX_load_verify_locations.");
					}
				}
				else {
					raise_error("Error SSL_CTX_load_verify_locations.");
				}
			}
		}
		else if (!arg.strCertaddr.empty()) {
			if (!SSL_CTX_load_verify_locations(ctx, NULL, arg.strCertaddr.c_str()))	{
				raise_error("Error SSL_CTX_load_verify_locations.");
			}
		}
		else {
			SSL_CTX_set_default_verify_paths(ctx);
		}
		bio = BIO_new_ssl_connect(ctx);
		BIO_get_ssl(bio, &ssl);
		//c_rehash / path / to / certfolder
		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
		std::string addr_req = url_adress + ":443";
		BIO_set_conn_hostname(bio, addr_req.c_str());
		if (BIO_do_connect(bio) <= 0){
			raise_error("Error BIO_do_connect.");
		}
		if (SSL_get_verify_result(ssl) != X509_V_OK){
			raise_error("Error SSL_get_verify_result.");
		}
		std::stringstream ss;
		BIO * out = BIO_new_fp(stdout, BIO_NOCLOSE);
		if (!(NULL != out)) {
			raise_error("Error BIO_new_fp.");
		}
		ss << "GET " << request << " HTTP/1.0\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1\r\n" <<
			"Host: " << url_adress << "\r\n" <<
			"Connection: close\r\n\r\n";
		std::string request = ss.str();
		// debug(request);
		BIO_puts(bio, request.c_str());
		BIO_puts(out, "\n");
	}

	void get_response_from_server() {
		char cur[102400];
		debug("BIO_read");
		int x = BIO_read(bio, cur, 102400);
		if (x == 0) {
			raise_error("Error BIO_read.");
		}
		else if (x < 0) {
			if (!BIO_should_retry(bio)) {
				raise_error("Error BIO_should_retry.");
			}
		}
		debug(cur);
		response = cur;
		while (true) {
			debug("BIO_read ... additional data");
			x = BIO_read(bio, cur, 102400);
			if (x <= 0) {
				break;
			}
			response.append(cur);
		}
		//debug(response);
		/*debug("BIO_reset.");
		BIO_reset(bio);
		debug("SSL_CTX_free." );
		SSL_CTX_free(ctx);
		debug("BIO_free_all.");
		BIO_free_all(bio);
		debug("returning");
		BIO_free_all(bio);*/
	}

	std::string parse_feed(std::string feed) {
		std::string str1 = str_before(str_after(feed, "<feed", true), "</feed>", true);
		str1 = str_after(str1, ">", true); // end of <feed xmlns...> tag
		str1 = str_after(str_after(str1, "<title", true), ">", true);
		std::string result = "*** " + str_before(str1, "</title>", true) + " ***\n";
		std::string entry = str_after(str_after(str1, "<entry", false), ">", false);
		bool entry_with_additional_info = false;
		while (!entry.empty()) {
			std::string one_entry = str_before(entry, "</entry>", true);
			std::string entry_url = "";
			std::string entry_updated = "";
			std::string entry_title = "";
			std::string entry_author = "";
			std::string entry_author_name = "";
			std::string entry_author_email = "";
			entry_title = str_before(str_after(str_after(one_entry, "<title", false), ">", false), "</title>", false);
			result.append(entry_title);
			result.append("\n");
			if (arg.isURLasoc) {
				entry_url = str_before(str_after(str_after(one_entry, "<link", false), "href=\"", false), "\"", false);
				if (!entry_url.empty()) {
					result.append("URL: ");
					result.append(entry_url);
					result.append("\n");
					entry_with_additional_info = true;
				}
			}
			if (arg.isAuthor) {
				entry_author = str_before(str_after(str_after(one_entry, "<author", false), ">", false), "</author>", false);
				if (!entry_author.empty()) {
					entry_author_name = str_before(str_after(str_after(entry_author, "<name", false), ">", false), "</name>", false);
					entry_author_email = str_before(str_after(str_after(entry_author, "<email", false), ">", false), "</email>", false);
					if (!entry_author_name.empty()) {
						if (!entry_author_email.empty()) {
							entry_author = entry_author_name + " " + entry_author_email;
						}
						else {
							entry_author = entry_author_name;
						}
					}
					else {
						if (!entry_author_email.empty()) {
							entry_author = entry_author_email;
						}
						else {
							entry_author = "";
						}
					}
					if (!entry_author.empty()) {
						result.append("Autor: ");
						result.append(entry_author);
						result.append("\n");
						entry_with_additional_info = true;
					}
				}
			}
			if (arg.isTimestamp) {
				entry_updated = str_before(str_after(str_after(one_entry, "<updated", false), ">", false), "</updated>", false);
				if (!entry_updated.empty()) {
					result.append("Aktualizace: ");
					result.append(entry_updated);
					result.append("\n");
					entry_with_additional_info = true;
				}
			}
			if (entry_with_additional_info) {
				result.append("\n");
			}
			entry_with_additional_info = false;
			entry = str_after(entry, "</entry>", true);
			entry = str_after(entry, "<entry>", false);
		}
		return result;
	}

	std::string get_feed() {
		return parse_feed(response);
	}

	std::string str_after(std::string strg, std::string key, bool exit_on_failure) {
		std::size_t pos = strg.find(key);
		if (pos != std::string::npos) {
			return strg.substr(pos + key.length());
		}
		if (exit_on_failure) {
			debug("String:\n" + key + "\nnot found in string:\n" + strg);
			raise_error("XML parsing error.");
		}
		return "";
	}

	std::string str_before(std::string strg, std::string key, bool exit_on_failure) {
		std::size_t pos = strg.find(key);
		if (pos != std::string::npos) {
			return strg.substr(0, pos);
		}
		if (exit_on_failure) {
			debug("String:\n" + key + "\nnot found in string:\n" + strg);
			raise_error("XML parsing error.");
		}
		return "";
	}

	void raise_error(std::string message, int err_code = 1) {
		std::cerr << message << std::endl;
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
		return_code = 1;
		throw 1;
		// exit(err_code);
	}

	void debug(std::string message) {
		if (arg.isDebugging) {
			std::cout << message << std::endl;
		}
	}
};


class Feedreader {
private:
	Argparser arg;
	std::vector<Feed> feeds;

public:
	int return_code;
	/**
	 * @brief Vytvori objekt klienta, potrebuje mit pristup k parametrum
	 * @param argp parametry po spusteni aplikace
	 */
	Feedreader(Argparser argp) {
		arg = argp;
		return_code = 0;
		prepare_feeds();
		// exit(0);
		for (auto i = feeds.begin(); i != feeds.end(); i++) {
			i->run();
		}
		bool is_first = true;
		for (auto u = feeds.begin(); u != feeds.end(); u++) {
			//std::cout << "\rtest message" << std::endl;
			if (arg.isFeedfile && !is_first) {
				std::cout << std::endl;
			}
			is_first = false;
			if (u->return_code == 0) {
				std::cout << u->get_feed();
			}
			else {
				return_code = 1;
			}
		}
	}

	/** Pripravi socket
	 * Nastavi timeout
	 */
	void prepare_feeds() {
		if (arg.isFeedfile) {
			std::ifstream input(arg.strFeedfile);
			for (std::string line; getline(input, line); ) {
				if (line.at(0) == '#' || line.length() == 1) {
					continue;
				}
				Feed feed(arg, line);
				feeds.push_back(feed);
			}
		}
		else {
			Feed feed(arg, arg.strURL);
			feeds.push_back(feed);
		}
	}
};

int main(int argc, char **argv) {
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	SSL_library_init();
	Argparser arg;
	arg.parse_arguments(argc, argv);
	Feedreader ff(arg);
	exit(ff.return_code);
}