#include <boost/asio.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/json.hpp>
#include <boost/url.hpp>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/entry.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/session.hpp>

#include <algorithm>
#include <iostream>
#include <map>
#include <regex>
#include <string>
#include <thread>

#include "alert_handler.hpp"
#include "range_parser.hpp"

using boost::asio::ip::tcp;

const char* ws = " \t\n\r\f\v";

// trim from end of string (right)
inline std::string& rtrim(std::string& s, const char* t = ws)
{
    s.erase(s.find_last_not_of(t) + 1);
    return s;
}

// trim from beginning of string (left)
inline std::string& ltrim(std::string& s, const char* t = ws)
{
    s.erase(0, s.find_first_not_of(t));
    return s;
}

// trim from both ends of string (right then left)
inline std::string& trim(std::string& s, const char* t = ws)
{
    return ltrim(rtrim(s, t), t);
}

struct request
{
	std::string method;
	std::string target;
	std::map<std::string, std::string> headers;
};

struct wrapped_file
{
    std::string Name;
    std::string URL;
    int64_t Length;
    std::string MimeType;
    int depth;
};

struct wrapped_torrent
{
    std::string Name;
    std::string InfoHash;
    std::vector<wrapped_file> Files;
    int64_t Length;
    std::string Playlist;
};

static boost::json::value to_json(const wrapped_file &file)
{
    return {
        {"Name", file.Name},
        {"URL", file.URL},
        {"Length", file.Length},
        {"MimeType", file.MimeType},
        {"depth", file.depth}};
}

static boost::json::value to_json(const wrapped_torrent &torrent)
{
    boost::json::array files_json;
    for (const wrapped_file &file : torrent.Files)
    {
        files_json.push_back(to_json(file));
    }

    return {
        {"Name", torrent.Name},
        {"InfoHash", torrent.InfoHash},
        {"Files", files_json},
        {"Length", torrent.Length},
        {"Playlist", torrent.Playlist}};
}

static lt::add_torrent_params get_torrent_params(std::string id)
{
    lt::add_torrent_params params;
    lt::error_code ec;

    params.ti = std::make_shared<lt::torrent_info>(id, ec);
    if (!ec)
        return params;

    params = lt::parse_magnet_uri(id, ec);
    if (!ec)
        return params;

    return lt::add_torrent_params{};
}

static std::string mime_type(std::string path)
{
    auto const ext = [&path]
    {
        auto const pos = path.rfind(".");
        if (pos == std::string::npos)
            return std::string{};
        return path.substr(pos);
    }();

    if (ext == ".htm")
        return "text/html";
    if (ext == ".html")
        return "text/html";
    if (ext == ".php")
        return "text/html";
    if (ext == ".css")
        return "text/css";
    if (ext == ".txt")
        return "text/plain";
    if (ext == ".js")
        return "application/javascript";
    if (ext == ".json")
        return "application/json";
    if (ext == ".xml")
        return "application/xml";

    if (ext == ".png")
        return "image/png";
    if (ext == ".jpe")
        return "image/jpeg";
    if (ext == ".jpeg")
        return "image/jpeg";
    if (ext == ".jpg")
        return "image/jpeg";
    if (ext == ".gif")
        return "image/gif";
    if (ext == ".bmp")
        return "image/bmp";
    if (ext == ".ico")
        return "image/vnd.microsoft.icon";
    if (ext == ".tiff")
        return "image/tiff";
    if (ext == ".tif")
        return "image/tiff";
    if (ext == ".svg")
        return "image/svg+xml";
    if (ext == ".svgz")
        return "image/svg+xml";

    if (ext == ".mp4")
        return "video/mp4";
    if (ext == ".mkv")
        return "video/x-matroska";
    if (ext == ".webm")
        return "video/webm";
    if (ext == ".ogv")
        return "video/ogg";
    if (ext == ".avi")
        return "video/x-msvideo";
    if (ext == ".mov")
        return "video/quicktime";
    if (ext == ".wmv")
        return "video/x-ms-wmv";
    if (ext == ".flv")
        return "video/x-flv";
    if (ext == ".mpeg")
        return "video/mpeg";
    if (ext == ".mpg")
        return "video/mpeg";
    if (ext == ".3gp")
        return "video/3gpp";
    if (ext == ".m4v")
        return "video/x-m4v";
    if (ext == ".ts")
        return "video/mp2t";
    if (ext == ".f4v")
        return "video/x-f4v";
    if (ext == ".rm")
        return "application/vnd.rn-realmedia";
    if (ext == ".rmvb")
        return "application/vnd.rn-realmedia-vbr";

    if (ext == ".mp3")
        return "audio/mpeg";
    if (ext == ".aac")
        return "audio/aac";
    if (ext == ".wav")
        return "audio/wav";
    if (ext == ".flac")
        return "audio/flac";
    if (ext == ".ogg")
        return "audio/ogg";
    if (ext == ".m4a")
        return "audio/mp4";
    if (ext == ".wma")
        return "audio/x-ms-wma";
    if (ext == ".alac")
        return "audio/alac";
    if (ext == ".aiff")
        return "audio/aiff";
    if (ext == ".opus")
        return "audio/opus";
    if (ext == ".ape")
        return "audio/ape";
    if (ext == ".amr")
        return "audio/amr";
    if (ext == ".mid")
        return "audio/midi";
    if (ext == ".xmf")
        return "audio/xmf";
    if (ext == ".rtttl")
        return "audio/x-rtttl";
    if (ext == ".midi")
        return "audio/midi";

    return "application/octet-stream"; // Default fallback MIME type
}


class HttpServer {
public:
    HttpServer(
		boost::asio::io_context& io_context,
		unsigned short port,
		std::size_t thread_count,
		handler::alert_handler &handler)
        : io_context_(io_context), acceptor_(io_context, tcp::endpoint(tcp::v4(), port)), thread_pool_(thread_count), handler_(handler) {
        accept();
    }

private:

	boost::asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    boost::asio::thread_pool thread_pool_;
	handler::alert_handler &handler_;

    void accept() {
        auto socket = std::make_shared<tcp::socket>(io_context_);
        acceptor_.async_accept(*socket, [this, socket](boost::system::error_code ec) {
            if (!ec) {
                boost::asio::post(thread_pool_, [this, socket]() {
                    handle_request(socket);
                });
            }
            accept();
        });
    }

    void handle_request(std::shared_ptr<tcp::socket> socket) {
    auto buffer = std::make_shared<boost::asio::streambuf>();
    boost::asio::async_read_until(*socket, *buffer, "\r\n\r\n",
        [this, socket, buffer](boost::system::error_code ec, std::size_t bytes_transferred) {
            if (!ec) {
                std::istream request_stream(buffer.get());
                std::string request_line;
                std::getline(request_stream, request_line);

                // Extract the request line
				request req;
                std::istringstream request_line_stream(request_line);
                request_line_stream >> req.method >> req.target;

                // Parse headers
                std::string header_line;
                while (std::getline(request_stream, header_line) && header_line != "\r") {
                    auto delimiter_pos = header_line.find(":");
                    if (delimiter_pos != std::string::npos) {
                        std::string key = header_line.substr(0, delimiter_pos);
                        std::string value = header_line.substr(delimiter_pos + 1);
                        // Trim whitespace
                        trim(key);
						trim(value);
                        req.headers[key] = value;
                    }
                }

                // Log headers
                // for (const auto& [key, value] : req.headers) {
                //     std::cout << "Header: " << key << " => " << value << std::endl;
                // }

                // Handle the request based on the method
				if (req.method == "GET" || req.method == "HEAD")
					handle_get(socket, req);
				else if (req.method == "POST")
					handle_post(socket, buffer, req);
				else
					handle_no_method(socket);
            }
        });
}


    void handle_post(std::shared_ptr<tcp::socket> socket, std::shared_ptr<boost::asio::streambuf> buffer, request &req) {
        std::istream request_stream(buffer.get());
        std::string body((std::istreambuf_iterator<char>(request_stream)), std::istreambuf_iterator<char>());

		if (req.target != "/torrents")
		{
			std::string content = "Forbidden";
			const std::string response =
				"HTTP/1.1 403\r\n"
				"Content-Type: text/plain\r\n"
				"Content-Length: " + std::to_string(content.length()) + "\r\n"
				"\r\n" + content;

			boost::asio::async_write(*socket, boost::asio::buffer(response),
				[socket](boost::system::error_code ec, std::size_t) {
					if (!ec) {
						socket->shutdown(tcp::socket::shutdown_send);
						socket->close();
					}
				});
			return;
		}

		lt::add_torrent_params params = get_torrent_params(body);
		lt::torrent_handle t = handler_.session.find_torrent(params.info_hashes.v1);

		if (!t.is_valid())
		{
			lt::error_code ec;
            t = handler_.session.add_torrent(params, ec);
            if (ec)
            {
				std::string content = "Failed to add torrent " + ec.message();
				const std::string response =
					"HTTP/1.1 200\r\n"
					"Content-Type: text/plain\r\n"
					"Content-Length: " + std::to_string(content.length()) + "\r\n"
					"\r\n" + content;

				boost::asio::async_write(*socket, boost::asio::buffer(response),
					[socket](boost::system::error_code ec, std::size_t) {
						if (!ec) {
							socket->shutdown(tcp::socket::shutdown_send);
							socket->close();
						}
					});
                return;
            }
		}

		handler_.wait_metadata(t);

		std::string content = build_playlist(wrap_files(socket, t.torrent_file()));
		const std::string response =
            "HTTP/1.1 200\r\n"
            "Content-Type: application/vnd.apple.mpegurl\r\n"
            "Content-Length: " + std::to_string(content.size()) + "\r\n"
            "\r\n" + content;

		boost::asio::async_write(*socket, boost::asio::buffer(response),
            [socket](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    socket->shutdown(tcp::socket::shutdown_send);
                    socket->close();
                }
            });
    }

    void handle_get(std::shared_ptr<tcp::socket> socket, request &req) {

		if (req.target == "/torrents")
		{
			boost::json::array torrents;
			for (auto &t : handler_.session.get_torrents())
			{
				std::shared_ptr<const lt::torrent_info> info = t.torrent_file();
				if (info == nullptr)
					continue;
				
				wrapped_torrent wt = wrap_torrent(socket, info);
				boost::json::value data = to_json(wt);
				torrents.push_back(data);
			}

			std::string content = boost::json::serialize(torrents);
			const std::string response =
				"HTTP/1.1 200\r\n"
				"Content-Type: application/json\r\n"
				"Content-Length: " + std::to_string(content.size()) + "\r\n"
				"\r\n" + (req.method == "GET" ? content : "");

			boost::asio::async_write(*socket, boost::asio::buffer(response),
				[socket](boost::system::error_code ec, std::size_t) {
					if (!ec) {
						socket->shutdown(tcp::socket::shutdown_send);
						socket->close();
					}
				});
			return;
		}

		if (std::regex_match(req.target, std::regex("^/torrents/([0-9a-fA-F]{40})$")))
		{
			std::string info_hash = req.target.substr(10);

			lt::sha1_hash sha1;
			lt::aux::from_hex(info_hash, sha1.data());
			lt::torrent_handle t = handler_.session.find_torrent(sha1);

			if (!t.is_valid())
			{
				std::string content = "Torrent not found";
				const std::string response =
					"HTTP/1.1 404\r\n"
					"Content-Type: text/plain\r\n"
					"Content-Length: " + std::to_string(content.size()) + "\r\n"
					"\r\n" + (req.method == "GET" ? content : "");

				boost::asio::async_write(*socket, boost::asio::buffer(response),
					[socket](boost::system::error_code ec, std::size_t) {
						if (!ec) {
							socket->shutdown(tcp::socket::shutdown_send);
							socket->close();
						}
					});
				return;
			}

			handler_.wait_metadata(t);

			std::string content = build_playlist(wrap_files(socket, t.torrent_file()));
			const std::string response =
				"HTTP/1.1 200\r\n"
				"Content-Type: application/json\r\n"
				"Content-Length: " + std::to_string(content.size()) + "\r\n"
				"\r\n" + (req.method == "GET" ? content : "");

			boost::asio::async_write(*socket, boost::asio::buffer(response),
				[socket](boost::system::error_code ec, std::size_t) {
					if (!ec) {
						socket->shutdown(tcp::socket::shutdown_send);
						socket->close();
					}
				});
			return;
		}

		if (std::regex_match(req.target, std::regex("^/torrents/([0-9a-fA-F]{40})/(.+)$")))
		{
			std::stringstream decoded;
			decoded << boost::urls::decode_view(req.target);

			std::string info_hash = req.target.substr(10,40);
			std::string path = decoded.str().substr(51);
            std::replace(path.begin(), path.end(), '/', '\\');

			lt::sha1_hash sha1;
			lt::aux::from_hex(info_hash, sha1.data());
			lt::torrent_handle t = handler_.session.find_torrent(sha1);

			if (!t.is_valid())
			{
				std::string content = "Torrent not found";
				const std::string response =
					"HTTP/1.1 404\r\n"
					"Content-Type: text/plain\r\n"
					"Content-Length: " + std::to_string(content.size()) + "\r\n"
					"\r\n" + (req.method == "GET" ? content : "");

				boost::asio::async_write(*socket, boost::asio::buffer(response),
					[socket](boost::system::error_code ec, std::size_t) {
						if (!ec) {
							socket->shutdown(tcp::socket::shutdown_send);
							socket->close();
						}
					});
				return;
			}

			handler_.wait_metadata(t);

			auto info = t.torrent_file();
			lt::file_index_t file_index{-1};
			lt::file_index_t file_count{info->num_files()};
			for (lt::file_index_t i{0}; i < file_count; i++)
			{
				if (info->files().file_path(i) == path)
				{
					file_index = i;
					break;
				}
			}

			if (file_index < lt::file_index_t(0))
			{
				std::string content = "File not found";
				const std::string response =
					"HTTP/1.1 404\r\n"
					"Content-Type: text/plain\r\n"
					"Content-Length: " + std::to_string(content.size()) + "\r\n"
					"\r\n" + (req.method == "GET" ? content : "");

				boost::asio::async_write(*socket, boost::asio::buffer(response),
					[socket](boost::system::error_code ec, std::size_t) {
						if (!ec) {
							socket->shutdown(tcp::socket::shutdown_send);
							socket->close();
						}
					});
				return;
			}
			
			int64_t size = info->files().file_size(file_index);

			range_parser::HTTPRange parsed;
			auto field = req.headers.find("Range");
			if (field == req.headers.end())
				parsed = range_parser::parse("bytes=0-", size);
			else
				parsed = range_parser::parse(field->second, size);

			range_parser::Range range = parsed.ranges.at(0);

			const std::string response =
				"HTTP/1.1 " + std::string(range.length < size ? "206" : "200") + "\r\n"
				"Accept-Ranges: bytes\r\n"
				"Content-Type: " + mime_type(path) + "\r\n"
				"Content-Length: " + std::to_string(range.length) + "\r\n" + 
				std::string(range.length < size ? "Content-Range: " + range.content_range(size) + "\r\n" : "") + "\r\n";
			
			boost::system::error_code ec;
			boost::asio::write(*socket, boost::asio::buffer(response), ec);
			if (ec)
				return;
			
			if (req.method == "HEAD")
			{
				socket->shutdown(tcp::socket::shutdown_send);
				socket->close();
				return;
			}

			lt::peer_request mappings = info->map_file(file_index, range.start, 0);
            lt::peer_request end_mappings = info->map_file(file_index, range.start + range.length, 0);

            lt::piece_index_t start_piece = mappings.piece;
            lt::piece_index_t end_piece = end_mappings.piece;
            int64_t end_piece_size = info->files().piece_size(end_piece);

            int start_offset = mappings.start;
            int end_offset = end_piece_size - ((range.start + range.length) - (int64_t(int(end_piece)) * info->files().piece_length()));

            for (lt::piece_index_t i = start_piece; i <= std::min(end_piece, lt::piece_index_t(int(start_piece) + 19)); i++)
            {
                t.set_piece_deadline(i, int(i - start_piece) * 2000);
            }

			int remaining_pieces = int(end_piece - start_piece) + 1;
			for (lt::piece_index_t i = start_piece; i <= end_piece; i++)
            {

				if (ec)
					break;

                auto p = handler_.schedule_piece(t, i);

                piece_entry piece_data;
                try
                {
                    piece_data = p.get();
                    if (lt::piece_index_t(int(i) + 20) <= end_piece)
                        t.set_piece_deadline(lt::piece_index_t(int(i) + 20), 20 * 2000);
                }
                catch (const std::future_error &)
                {
                    break;
                }

                char *buffer_start = piece_data.buffer.get();
                int piece_size = piece_data.size;

                if (i == start_piece)
                {
                    buffer_start += start_offset;
                    piece_size -= start_offset;
                }

                if (i == end_piece)
                    piece_size -= end_offset;

                do
                {
                    int written = boost::asio::write(*socket, boost::asio::buffer(buffer_start, piece_size), ec);
                    buffer_start += written;
                    piece_size -= written;
                } while (!ec && piece_size);

				if (!ec)
					remaining_pieces--;
				
            }

			socket->shutdown(tcp::socket::shutdown_both);
			socket->close();

			return;
		}

        if (req.target == "/shutdown")
        {
            std::string content = "Server shutting down...";
            const std::string response =
            "HTTP/1.1 403\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: " + std::to_string(content.size()) + "\r\n"
            "\r\n" + content;

            boost::asio::async_write(*socket, boost::asio::buffer(response),
                [this, socket](boost::system::error_code ec, std::size_t) {
                    if (!ec) {
                        socket->shutdown(tcp::socket::shutdown_send);
                        socket->close();
                    }
                    io_context_.stop();
                });
            return;
        }

		std::string content = "Forbidden";
		
    }

	void handle_no_method(std::shared_ptr<tcp::socket> socket)
	{
		std::string content = "Method not allowed";
		const std::string response =
            "HTTP/1.1 405\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: " + std::to_string(content.size()) + "\r\n"
            "\r\n" + content;

        boost::asio::async_write(*socket, boost::asio::buffer(response),
            [socket](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    socket->shutdown(tcp::socket::shutdown_send);
                    socket->close();
                }
            });
	}


	std::string build_playlist(std::vector<wrapped_file> wf)
    {
        std::string playlist;

        playlist.append("#EXTM3U\n");
        for (auto &f : wf)
        {
            if (f.MimeType.find("video") == std::string::npos)
                continue;
            playlist.append("#EXTINF:0," + f.Name + "\n");
            playlist.append(f.URL + "\n");
        }

        return playlist;
    }

    wrapped_torrent wrap_torrent(std::shared_ptr<tcp::socket> socket, std::shared_ptr<const lt::torrent_info> info)
    {
        wrapped_torrent torrent;
        std::vector<wrapped_file> files = wrap_files(socket, info);
        torrent.Name = info->name();
        torrent.InfoHash = lt::aux::to_hex(info->info_hashes().v1);
        torrent.Files = files;
        torrent.Length = info->total_size();
        torrent.Playlist = build_playlist(files);

        return torrent;
    }

    std::vector<wrapped_file> wrap_files(std::shared_ptr<tcp::socket> socket, std::shared_ptr<const lt::torrent_info> info)
    {
        int n = info->num_files();

        std::vector<wrapped_file> files;
        files.reserve(n);

        std::string address = socket->local_endpoint().address().to_string();
        std::string port = std::to_string(socket->local_endpoint().port());

        for (lt::file_index_t i{0}; i < lt::file_index_t(n); i++)
        {
            wrapped_file f;
            std::string path = info->files().file_path(i);
            std::replace(path.begin(), path.end(), '\\', '/');

            std::size_t pos = path.rfind("/") + 1;
            f.Name = path.substr(pos);
            f.URL = "http://" + address + ":" + port + "/torrents/" + lt::aux::to_hex(info->info_hashes().v1) + "/" + path;
            f.Length = info->files().file_size(i);
            f.MimeType = mime_type(path);
            f.depth = 0;

            for (std::size_t c = 0; c < path.length(); c++)
                if (path[c] == '/')
                    f.depth++;

            files.push_back(f);
        }

        std::sort(files.begin(), files.end(), [](wrapped_file a, wrapped_file b)
                  {
            if (a.depth != b.depth)
                return a.depth < b.depth;
            return a.Name < b.Name; });

        return files;
    }
};

void run() {
    boost::asio::io_context io_context;
    std::size_t thread_count = std::thread::hardware_concurrency();
    if (thread_count == 0) {
        thread_count = 4;
    }

    lt::session_params params;
    params.settings.set_int(lt::settings_pack::alert_mask, lt::alert_category::status | lt::alert_category::storage | lt::alert_category::piece_progress);
    params.settings.set_int(lt::settings_pack::connection_speed, 200);
    params.settings.set_int(lt::settings_pack::smooth_connects, false);
    lt::session ses(params);
    handler::alert_handler handler(ses);

    HttpServer server(io_context, 8080, thread_count, handler);
    std::cout << "Server running on port 8080 with " << thread_count << " threads..." << std::endl;

    std::vector<std::thread> threads;
    for (std::size_t i = 0; i < thread_count; ++i) {
        threads.emplace_back([&io_context]() {
            io_context.run();
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }
}

int main() {
    try {
        run();
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
