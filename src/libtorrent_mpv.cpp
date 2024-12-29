#include "alert_handler.hpp"
#include "range_parser.hpp"
#include <algorithm>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/filesystem.hpp>
#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <boost/url.hpp>
#include <fstream>
#include <functional>
#include <iostream>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/entry.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/read_resume_data.hpp>
#include <libtorrent/session.hpp>
#include <map>
#include <regex>
#include <string>
#include <thread>

namespace beast = boost::beast;
namespace net = boost::asio;
using boost::asio::ip::tcp;

const char *ws = " \t\n\r\f\v";

// trim from end of string (right)
inline std::string &rtrim(std::string &s, const char *t = ws) {
  s.erase(s.find_last_not_of(t) + 1);
  return s;
}

// trim from beginning of string (left)
inline std::string &ltrim(std::string &s, const char *t = ws) {
  s.erase(0, s.find_first_not_of(t));
  return s;
}

// trim from both ends of string (right then left)
inline std::string &trim(std::string &s, const char *t = ws) {
  return ltrim(rtrim(s, t), t);
}

struct request {
  std::string method;
  std::string target;
  std::map<std::string, std::string> headers;
  bool keep_alive;
};

struct response {
  int status;
  std::map<std::string, std::string> headers;
  std::string content;
  bool keep_alive;
};

struct wrapped_file {
  std::string Name;
  std::string URL;
  int64_t Length;
  std::string MimeType;
  int depth;
};

struct wrapped_torrent {
  std::string Name;
  std::string InfoHash;
  std::vector<wrapped_file> Files;
  int64_t Length;
  std::string Playlist;
};

static boost::json::value to_json(const wrapped_file &file) {
  return {{"Name", file.Name},
          {"URL", file.URL},
          {"Length", file.Length},
          {"MimeType", file.MimeType},
          {"depth", file.depth}};
}

static boost::json::value to_json(const wrapped_torrent &torrent) {
  boost::json::array files_json;
  for (const wrapped_file &file : torrent.Files) {
    files_json.push_back(to_json(file));
  }

  return {{"Name", torrent.Name},
          {"InfoHash", torrent.InfoHash},
          {"Files", files_json},
          {"Length", torrent.Length},
          {"Playlist", torrent.Playlist}};
}

static lt::add_torrent_params get_torrent_params(std::string id) {
  lt::add_torrent_params params;
  lt::error_code ec;

  params.ti = std::make_shared<lt::torrent_info>(id, ec);
  if (!ec)
    return params;

  params = lt::parse_magnet_uri(id, ec);
  if (!ec)
    return params;

  if (std::regex_match(id, std::regex("^([0-9a-fA-F]{40})$"))) {
    lt::sha1_hash sha1;
    lt::aux::from_hex(id, sha1.data());
    params.info_hashes.v1 = sha1;
    return params;
  }

  auto const ext = [&id] {
    auto const pos = id.rfind(".");
    if (pos == std::string::npos)
      return std::string{};
    return id.substr(pos);
  }();

  if (ext == ".fastresume") {
    std::ifstream in(id, std::ios_base::binary);
    std::vector<char> buf(std::istreambuf_iterator<char>(in), {});
    return lt::read_resume_data(buf);
  }

  return lt::add_torrent_params{};
}

static std::string mime_type(std::string path) {
  auto const ext = [&path] {
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

void fail(beast::error_code ec, char const *what) {
  std::cerr << what << ": " << ec.message() << "\n";
}

class http_session : public std::enable_shared_from_this<http_session> {
  beast::tcp_stream stream_;
  tcp::endpoint ep_ = stream_.socket().remote_endpoint();
  std::shared_ptr<handler::alert_handler> handler_;
  std::function<void()> shutdown_;

public:
  http_session(tcp::socket &&socket,
               std::shared_ptr<handler::alert_handler> handler,
               std::function<void()> shutdown)
      : stream_(std::move(socket)), handler_(handler), shutdown_(shutdown) {
    std::cerr << "HTTP session (" << ep_ << ")" << std::endl;
  }

  ~http_session() {
    std::cerr << "HTTP session destroyed (" << ep_ << ")" << std::endl;
  }

  void start() {
    net::dispatch(stream_.get_executor(),
                  std::bind(&http_session::do_read, this->shared_from_this()));
  }

private:
  void do_read() {
    auto buffer = std::make_shared<net::streambuf>();
    using namespace std::placeholders;
    net::async_read_until(stream_, *buffer, "\r\n\r\n",
                          std::bind(&http_session::on_read,
                                    this->shared_from_this(), _1, _2, buffer));
  }

  void on_read(boost::system::error_code ec, std::size_t,
               std::shared_ptr<net::streambuf> buffer) {

    if (ec == net::error::eof)
      return do_close();

    if (ec)
      return fail(ec, "read");

    std::istream request_stream(buffer.get());
    std::string request_line;
    std::getline(request_stream, request_line);

    // Extract the request line
    request req{};
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

    if (!req.headers.count("Connection"))
      req.keep_alive = true;
    else
      req.keep_alive = req.headers["Connection"] == "keep-alive";

    // Handle the request based on the method
    if (req.method == "GET" || req.method == "HEAD")
      handle_get(std::move(req));
    else if (req.method == "POST")
      handle_post(std::move(req), buffer);
    else
      handle_no_method(std::move(req));
  }

  void do_write(const response &&res) {
    std::string buf = "HTTP/1.1 " + std::to_string(res.status) + "\r\n";
    for (auto &h : res.headers)
      buf += h.first + ": " + h.second + "\r\n";

    buf += "\r\n" + res.content;

    using namespace std::placeholders;
    net::async_write(stream_, net::buffer(buf),
                     std::bind(&http_session::on_write,
                               this->shared_from_this(), _1, _2,
                               res.keep_alive));
  }

  void on_write(boost::system::error_code ec, std::size_t, bool keep_alive) {
    if (ec)
      return fail(ec, "write");

    if (!keep_alive)
      return do_close();

    do_read();
  }

  void do_close() {
    boost::system::error_code ec;
    stream_.socket().shutdown(tcp::socket::shutdown_both, ec);
  }

  void handle_get(const request &&req) {
    response res{};
    res.keep_alive = req.keep_alive;
    res.headers["Connection"] = (req.keep_alive ? "keep-alive" : "close");

    if (req.target == "/torrents") {
      boost::json::array torrents;
      for (auto &t : handler_->session.get_torrents()) {
        std::shared_ptr<const lt::torrent_info> info = t.torrent_file();
        if (info == nullptr)
          continue;

        wrapped_torrent wt = wrap_torrent(info);
        boost::json::value data = to_json(wt);
        torrents.push_back(data);
      }

      std::string content = boost::json::serialize(torrents);
      res.status = 200;
      res.headers["Content-Type"] = "application/json";
      res.headers["Content-Length"] = std::to_string(content.length());
      if (req.method == "GET")
        res.content = std::move(content);

      return do_write(std::move(res));
    }

    if (std::regex_match(req.target,
                         std::regex("^/torrents/([0-9a-fA-F]{40})$"))) {
      std::string info_hash = req.target.substr(10);

      lt::sha1_hash sha1;
      lt::aux::from_hex(info_hash, sha1.data());
      lt::torrent_handle t = handler_->session.find_torrent(sha1);

      if (!t.is_valid()) {
        std::string content = "Torrent not found";
        res.status = 404;
        res.headers["Content-Type"] = "text/plain";
        res.headers["Content-Length"] = std::to_string(content.length());
        if (req.method == "GET")
          res.content = std::move(content);

        return do_write(std::move(res));
      }

      handler_->wait_metadata(t);

      std::string content = build_playlist(wrap_files(t.torrent_file()));
      res.status = 200;
      res.headers["Content-Type"] = "application/json";
      res.headers["Content-Length"] = std::to_string(content.length());
      if (req.method == "GET")
        res.content = std::move(content);

      return do_write(std::move(res));
    }

    if (std::regex_match(req.target,
                         std::regex("^/torrents/([0-9a-fA-F]{40})/(.+)$"))) {
      std::stringstream decoded;
      decoded << boost::urls::decode_view(req.target);

      std::string info_hash = req.target.substr(10, 40);
      std::string path = decoded.str().substr(51);
      std::replace(path.begin(), path.end(), '/', '\\');

      lt::sha1_hash sha1;
      lt::aux::from_hex(info_hash, sha1.data());
      lt::torrent_handle t = handler_->session.find_torrent(sha1);

      if (!t.is_valid()) {
        std::string content = "Torrent not found";
        res.status = 404;
        res.headers["Content-Type"] = "text/plain";
        res.headers["Content-Length"] = std::to_string(content.length());
        if (req.method == "GET")
          res.content = std::move(content);

        return do_write(std::move(res));
      }

      handler_->wait_metadata(t);

      auto info = t.torrent_file();
      lt::file_index_t file_index{-1};
      lt::file_index_t file_count{info->num_files()};
      for (lt::file_index_t i{0}; i < file_count; i++) {
        if (info->files().file_path(i) == path) {
          file_index = i;
          break;
        }
      }

      if (file_index < lt::file_index_t(0)) {
        std::string content = "File not found";
        res.status = 404;
        res.headers["Content-Type"] = "text/plain";
        res.headers["Content-Length"] = std::to_string(content.length());
        if (req.method == "GET")
          res.content = std::move(content);

        return do_write(std::move(res));
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
          "HTTP/1.1 " + std::string(range.length < size ? "206" : "200") +
          "\r\n"
          "Accept-Ranges: bytes\r\n"
          "Connection: " +
          std::string(req.keep_alive ? "keep-alive" : "close") +
          "\r\n"
          "Content-Type: " +
          mime_type(path) +
          "\r\n"
          "Content-Length: " +
          std::to_string(range.length) + "\r\n" +
          std::string(range.length < size
                          ? "Content-Range: " + range.content_range(size) +
                                "\r\n"
                          : "") +
          "\r\n";

      boost::system::error_code ec;
      std::size_t written = net::write(stream_, net::buffer(response), ec);

      if (req.method == "HEAD" || ec)
        return on_write(ec, written, req.keep_alive);

      lt::peer_request mappings = info->map_file(file_index, range.start, 0);
      lt::peer_request end_mappings =
          info->map_file(file_index, range.start + range.length, 0);

      lt::piece_index_t start_piece = mappings.piece;
      lt::piece_index_t end_piece = end_mappings.piece;
      int64_t end_piece_size = info->files().piece_size(end_piece);

      int start_offset = mappings.start;
      int end_offset =
          end_piece_size -
          ((range.start + range.length) -
           (int64_t(int(end_piece)) * info->files().piece_length()));

      for (lt::piece_index_t i = start_piece;
           i <= std::min(end_piece, lt::piece_index_t(int(start_piece) + 19));
           i++) {
        t.set_piece_deadline(i, int(i - start_piece) * 2000);
      }

      int remaining_pieces = int(end_piece - start_piece) + 1;
      std::size_t total_written = written;
      for (lt::piece_index_t i = start_piece; i <= end_piece; i++) {
        auto p = handler_->schedule_piece(t, i);

        piece_entry piece_data;
        try {
          piece_data = p.get();
          if (lt::piece_index_t(int(i) + 20) <= end_piece)
            t.set_piece_deadline(lt::piece_index_t(int(i) + 20), 20 * 2000);
        } catch (const std::future_error &) {
          break;
        }

        char *buffer_start = piece_data.buffer.get();
        int piece_size = piece_data.size;

        if (i == start_piece) {
          buffer_start += start_offset;
          piece_size -= start_offset;
        }

        if (i == end_piece)
          piece_size -= end_offset;

        written +=
            net::write(stream_, net::buffer(buffer_start, piece_size), ec);

        if (!ec)
          remaining_pieces--;
        else
          break;
      }

      return on_write(ec, total_written, req.keep_alive);
    }

    if (req.target == "/shutdown") {
      std::string content = "Server shutting down...";
      res.status = 200;
      res.keep_alive = false;
      res.headers["Connection"] = "close";
      res.headers["Content-Type"] = "text/plain";
      res.headers["Content-Length"] = std::to_string(content.length());
      if (req.method == "GET")
        res.content = std::move(content);

      do_write(std::move(res));
      return shutdown_();
    }

    std::string content = "Forbidden";
    res.status = 403;
    res.headers["Content-Type"] = "text/plain";
    res.headers["Content-Length"] = std::to_string(content.length());
    if (req.method == "GET")
      res.content = std::move(content);

    return do_write(std::move(res));
  }

  void handle_post(const request &&req,
                   std::shared_ptr<net::streambuf> buffer) {
    std::istream request_stream(buffer.get());
    std::string body((std::istreambuf_iterator<char>(request_stream)),
                     std::istreambuf_iterator<char>());
    response res{};
    res.keep_alive = req.keep_alive;
    res.headers["Connection"] = (req.keep_alive ? "keep-alive" : "close");

    if (req.target != "/torrents") {
      std::string content = "Forbidden";
      res.status = 403;
      res.headers["Content-Type"] = "text/plain";
      res.headers["Content-Length"] = std::to_string(content.length());
      res.content = std::move(content);

      return do_write(std::move(res));
    }

    lt::add_torrent_params params = get_torrent_params(body);
    params.save_path = handler_->save_path.string();
    lt::torrent_handle t =
        handler_->session.find_torrent(params.info_hashes.v1);

    if (!t.is_valid()) {
      lt::error_code ec;
      t = handler_->session.add_torrent(params, ec);
      if (ec) {
        std::string content = "Failed to add torrent " + ec.message();
        res.status = 400;
        res.headers["Content-Type"] = "text/plain";
        res.headers["Content-Length"] = std::to_string(content.length());
        res.content = std::move(content);

        return do_write(std::move(res));
      }
    }

    handler_->wait_metadata(t);

    std::string content = build_playlist(wrap_files(t.torrent_file()));
    res.status = 200;
    res.headers["Content-Type"] = "application/vnd.apple.mpegurl";
    res.headers["Content-Length"] = std::to_string(content.length());
    if (req.method == "POST")
      res.content = std::move(content);

    return do_write(std::move(res));
  }

  void handle_no_method(const request &&req) {
    std::string content = "Method not allowed";
    response res{};
    res.keep_alive = req.keep_alive;
    res.status = 405;
    res.headers["Connection"] = (req.keep_alive ? "keep-alive" : "close");
    res.headers["Content-Type"] = "text/plain";
    res.headers["Content-Length"] = std::to_string(content.length());
    res.content = std::move(content);

    return do_write(std::move(res));
  }

  std::string build_playlist(const std::vector<wrapped_file> wf) {
    std::string playlist;

    playlist.append("#EXTM3U\n");
    for (auto &f : wf) {
      if (f.MimeType.find("video") == std::string::npos)
        continue;
      playlist.append("#EXTINF:0," + f.Name + "\n");
      playlist.append(f.URL + "\n");
    }

    return playlist;
  }

  wrapped_torrent wrap_torrent(std::shared_ptr<const lt::torrent_info> info) {
    std::vector<wrapped_file> files = wrap_files(info);

    return wrapped_torrent{info->name(),
                           lt::aux::to_hex(info->info_hashes().v1), files,
                           info->total_size(), build_playlist(files)};
  }

  std::vector<wrapped_file>
  wrap_files(std::shared_ptr<const lt::torrent_info> info) {
    int n = info->num_files();

    std::vector<wrapped_file> files;
    files.reserve(n);

    std::string address =
        stream_.socket().local_endpoint().address().to_string();
    std::string port = std::to_string(stream_.socket().local_endpoint().port());

    for (lt::file_index_t i{0}; i < lt::file_index_t(n); i++) {
      wrapped_file f;
      std::string path = info->files().file_path(i);
      std::replace(path.begin(), path.end(), '\\', '/');

      std::size_t pos = path.rfind("/") + 1;
      f.Name = path.substr(pos);
      f.URL = "http://" + address + ":" + port + "/torrents/" +
              lt::aux::to_hex(info->info_hashes().v1) + "/" + path;
      f.Length = info->files().file_size(i);
      f.MimeType = mime_type(path);
      f.depth = 0;

      for (std::size_t c = 0; c < path.length(); c++)
        if (path[c] == '/')
          f.depth++;

      files.push_back(f);
    }

    std::sort(files.begin(), files.end(), [](wrapped_file a, wrapped_file b) {
      if (a.depth != b.depth)
        return a.depth < b.depth;
      return a.Name < b.Name;
    });

    return files;
  }
};

class listener {
  net::any_io_executor ex_;
  tcp::acceptor acceptor_;
  std::shared_ptr<handler::alert_handler> handler_;
  std::atomic_bool shutdown_;

public:
  listener(net::any_io_executor ex, tcp::endpoint endpoint,
           std::shared_ptr<handler::alert_handler> handler)
      : ex_(ex), acceptor_(net::make_strand(ex), endpoint), handler_(handler),
        shutdown_(false) {
    acceptor_.set_option(net::socket_base::reuse_address(true));
    accept_loop();
  }

  void shutdown() {
    shutdown_ = true;
    net::dispatch(acceptor_.get_executor(), [this] { acceptor_.cancel(); });
  }

private:
  void accept_loop() {
    // The new connection gets its own strand
    acceptor_.async_accept(
        net::make_strand(ex_),
        [this](boost::system::error_code ec, tcp::socket socket) {
          if (!ec)
            std::make_shared<http_session>(std::move(socket), handler_,
                                           std::bind(&listener::shutdown, this))
                ->start();
          else
            fail(ec, "accept");

          if (!shutdown_)
            accept_loop();
        });
  }
};

int main(int argc, char **argv) {

  namespace po = boost::program_options;
  namespace fs = boost::filesystem;

  po::options_description desc("Allowed options");
  desc.add_options()("help", "produce help")(
      "address", po::value<std::string>()->default_value("0.0.0.0"),
      "HTTP server address")("port", po::value<uint16_t>()->default_value(1337),
                             "HTTP server port")(
      "threads",
      po::value<size_t>()->default_value(std::thread::hardware_concurrency()),
      "HTTP server threads")("save-path",
                             po::value<fs::path>()->default_value("."),
                             "Directory where downloaded files are stored");

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  auto const address =
      net::ip::make_address(vm.at("address").as<std::string>());
  auto const port = vm.at("port").as<uint16_t>();
  auto const threads = std::max<size_t>(1, vm.at("threads").as<size_t>());
  auto const save_path = vm.at("save-path").as<fs::path>();

  auto const resume_path = save_path / "resume_data";

  if (!(fs::exists(save_path) && fs::is_directory(save_path))) {
    std::cerr << "Invalid save path '" << save_path << "'" << std::endl;
    return 1;
  }

  net::thread_pool ioc{threads};
  lt::session_params params;
  params.settings.set_int(lt::settings_pack::alert_mask,
                          lt::alert_category::status |
                              lt::alert_category::storage |
                              lt::alert_category::piece_progress);
  params.settings.set_int(lt::settings_pack::torrent_connect_boost, 100);
  params.settings.set_int(lt::settings_pack::connection_speed, 200);
  params.settings.set_int(lt::settings_pack::smooth_connects, false);
  lt::session ses(params);
  auto handler = std::make_shared<handler::alert_handler>(ses, save_path);

  if (!fs::exists(resume_path))
    fs::create_directory(resume_path);

  for (auto &entry : fs::directory_iterator(resume_path)) {
    if (entry.path().extension() != ".fastresume")
      continue;
    ses.add_torrent(get_torrent_params(entry.path().string()));
  }

  listener lsnr(ioc.get_executor(), tcp::endpoint{address, port}, handler);
  std::cout << "Server running on port " << port << " with " << threads
            << " threads..." << std::endl;

  ioc.join();

  return 0;
}
