#include "alert_handler.hpp"
#include "range_parser.hpp"
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/container/flat_set.hpp>
#include <boost/filesystem.hpp>
#include <boost/json.hpp>
#include <boost/program_options.hpp>
#include <boost/url.hpp>
#include <fstream>
#include <iostream>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/entry.hpp>
#include <libtorrent/hex.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/read_resume_data.hpp>
#include <libtorrent/session.hpp>
#include <map>
#include <regex>
#include <string>
#include <thread>

namespace net = boost::asio;
using boost::asio::ip::tcp;

std::string getLocalIp() {
  char host[256];
  if (gethostname(host, sizeof(host)) != 0)
    return "";

  struct hostent *he = gethostbyname(host);
  if (he == nullptr)
    return "";

  struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
  if (addr_list[0] != nullptr)
    return inet_ntoa(*addr_list[0]); // Return the first IP address found

  return "";
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

  wrapped_file(const std::string &name, const std::string &url, int64_t length,
               const std::string &mime, int d)
      : Name(name), URL(url), Length(length), MimeType(mime), depth(d) {}

  bool operator<(const wrapped_file &other) const {
    return std::tie(depth, Name, URL) <
           std::tie(other.depth, other.Name, other.URL);
  }
};

struct wrapped_torrent {
  std::string Name;
  std::string InfoHash;
  boost::container::flat_set<wrapped_file> Files;
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

static lt::add_torrent_params get_torrent_params(const std::string &id) {
  lt::add_torrent_params params;
  lt::error_code ec;

  auto const pos = id.rfind(".");
  std::string ext;
  if (pos == std::string::npos)
    ext = std::string{};
  else
    ext = id.substr(pos);

  if (ext == ".fastresume") {
    std::ifstream in(id, std::ios_base::binary);
    std::vector<char> buf(std::istreambuf_iterator<char>(in), {});
    return lt::read_resume_data(buf, ec);
  }

  params.ti = std::make_shared<lt::torrent_info>(id, ec);
  if (!ec)
    return params;

  params = lt::parse_magnet_uri(id, ec);
  if (!ec)
    return params;

  if (std::regex_search(id, std::regex("^([0-9a-fA-F]{40})$"))) {
    lt::sha1_hash sha1;
    lt::aux::from_hex(id, sha1.data());
    params.info_hashes.v1 = sha1;
    return params;
  }

  return lt::add_torrent_params{};
}

static std::string mime_type(const std::string &path) {
  static const std::unordered_map<std::string, std::string> mime_types = {
      {".htm", "text/html"},
      {".html", "text/html"},
      {".php", "text/html"},
      {".css", "text/css"},
      {".txt", "text/plain"},
      {".js", "application/javascript"},
      {".json", "application/json"},
      {".xml", "application/xml"},

      {".png", "image/png"},
      {".jpe", "image/jpeg"},
      {".jpeg", "image/jpeg"},
      {".jpg", "image/jpeg"},
      {".gif", "image/gif"},
      {".bmp", "image/bmp"},
      {".ico", "image/vnd.microsoft.icon"},
      {".tiff", "image/tiff"},
      {".tif", "image/tiff"},
      {".svg", "image/svg+xml"},
      {".svgz", "image/svg+xml"},

      {".mp4", "video/mp4"},
      {".mkv", "video/x-matroska"},
      {".webm", "video/webm"},
      {".ogv", "video/ogg"},
      {".avi", "video/x-msvideo"},
      {".mov", "video/quicktime"},
      {".wmv", "video/x-ms-wmv"},
      {".flv", "video/x-flv"},
      {".mpeg", "video/mpeg"},
      {".mpg", "video/mpeg"},
      {".3gp", "video/3gpp"},
      {".m4v", "video/x-m4v"},
      {".ts", "video/mp2t"},
      {".f4v", "video/x-f4v"},
      {".rm", "application/vnd.rn-realmedia"},
      {".rmvb", "application/vnd.rn-realmedia-vbr"},

      {".mp3", "audio/mpeg"},
      {".aac", "audio/aac"},
      {".wav", "audio/wav"},
      {".flac", "audio/flac"},
      {".ogg", "audio/ogg"},
      {".m4a", "audio/mp4"},
      {".wma", "audio/x-ms-wma"},
      {".alac", "audio/alac"},
      {".aiff", "audio/aiff"},
      {".opus", "audio/opus"},
      {".ape", "audio/ape"},
      {".amr", "audio/amr"},
      {".mid", "audio/midi"},
      {".xmf", "audio/xmf"},
      {".rtttl", "audio/x-rtttl"},
      {".midi", "audio/midi"}};

  auto const pos = path.rfind(".");
  if (pos == std::string::npos)
    return "application/octet-stream";

  std::string ext = path.substr(pos);
  auto it = mime_types.find(ext);
  if (it != mime_types.end()) {
    return it->second;
  }

  return "application/octet-stream";
}

void fail(const boost::system::error_code &ec, char const *what) {
  std::cerr << what << ": " << ec.message() << "\n";
}

class stop_token {
  std::atomic<bool> stop_{false};
  mutable std::mutex callback_mtx_;
  std::map<std::size_t, std::function<void()>> callbacks_;
  std::condition_variable cv;
  std::size_t next_callback_id_ = 0; // Unique ID for each callback

public:
  stop_token() = default;

  // Request stop and invoke callbacks
  void request_stop() {
    std::lock_guard<std::mutex> lock(callback_mtx_);
    if (stop_.exchange(true)) {
      return; // Stop already requested
    }
    for (const auto &entry : callbacks_) {
      if (entry.second) {
        entry.second();
      }
    }
    cv.notify_all();
  }

  // Check if stop is requested
  bool stop_requested() const { return stop_.load(); }

  // Register a callback, returns a unique ID
  std::size_t add_callback(std::function<void()> &&callback) {
    std::lock_guard<std::mutex> lock(callback_mtx_);
    if (stop_.load()) {
      callback();
      return 0; // Callback executed immediately, no ID needed
    } else {
      std::size_t id = next_callback_id_++;
      callbacks_[id] = std::move(callback);
      return id;
    }
  }

  // Remove a callback by its ID
  void remove_callback(std::size_t id) {
    std::lock_guard<std::mutex> lock(callback_mtx_);
    callbacks_.erase(id);
  }

  void wait_stop() {
    std::unique_lock<std::mutex> lock(callback_mtx_);
    if (stop_.load())
      return;
    cv.wait(lock);
  }
};

class http_session : public std::enable_shared_from_this<http_session> {
  tcp::socket socket_;
  std::shared_ptr<lt::session> session_;
  std::shared_ptr<handler::alert_handler> handler_;
  stop_token &token_;
  tcp::endpoint ep_;
  std::shared_ptr<net::streambuf> buffer_;

public:
  http_session(tcp::socket &&socket,
               std::shared_ptr<handler::alert_handler> handler,
               stop_token &token)
      : socket_(std::move(socket)), session_(handler->session),
        handler_(handler), token_(token), ep_(socket_.remote_endpoint()) {
    socket_.set_option(net::socket_base::keep_alive(true));
    socket_.set_option(tcp::no_delay(true));
    std::cerr << "HTTP session (" << ep_ << ")\n";
  }

  ~http_session() { std::cerr << "HTTP session destroyed (" << ep_ << ")\n"; }

  void run() { do_read(); }

private:
  void do_read() {
    buffer_.reset(new net::streambuf());
    net::async_read_until(
        socket_, *buffer_, "\r\n\r\n",
        [self = shared_from_this()](const boost::system::error_code &ec,
                                    std::size_t bytes_read) {
          self->on_read(ec, bytes_read);
        });
  }

  void on_read(const boost::system::error_code &ec, std::size_t) {

    if (ec == net::error::eof)
      return do_close();

    if (ec)
      return fail(ec, "read");

    std::istream request_stream(buffer_.get());
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
        boost::trim(key);
        boost::trim(value);
        req.headers[key] = value;
      }
    }

    if (!req.headers.count("Connection"))
      req.keep_alive = true;
    else
      req.keep_alive = req.headers["Connection"] == "keep-alive";

    // Handle the request based on the method
    if (req.method == "GET" || req.method == "HEAD")
      handle_get(req);
    else if (req.method == "POST")
      handle_post(req);
    else if (req.method == "DELETE")
      handle_delete(req);
    else
      handle_no_method(req);
  }

  void do_write(const response &res) {
    std::string buf = "HTTP/1.1 " + std::to_string(res.status) + "\r\n";
    for (auto &h : res.headers)
      buf += h.first + ": " + h.second + "\r\n";

    buf += "\r\n" + res.content;

    net::async_write(
        socket_, net::buffer(buf),
        [self = shared_from_this(), keep_alive = res.keep_alive](
            const boost::system::error_code &ec, std::size_t written) {
          self->on_write(ec, written, keep_alive);
        });
  }

  void on_write(const boost::system::error_code &ec, std::size_t,
                const bool keep_alive) {
    if (ec)
      return fail(ec, "write");

    if (!keep_alive)
      return do_close();

    do_read();
  }

  void do_stream(lt::torrent_handle t, const lt::piece_index_t start_piece,
                 const lt::piece_index_t end_piece, lt::piece_index_t piece,
                 const int start_offset, const int end_offset,
                 const bool keep_alive, std::size_t written = 0) {
    handler_->schedule_piece(
        t, piece,
        [self = shared_from_this(), t, start_piece, end_piece, piece,
         start_offset, end_offset, keep_alive,
         written](piece_entry piece_data) {
          if (piece_data.buffer == nullptr) {
            std::cout << "interrupted: " << start_piece << "-" << end_piece
                      << " " << piece << "\n";
            return self->on_write(
                net::error::make_error_code(net::error::interrupted), written,
                keep_alive);
          }

          char *buffer_start = piece_data.buffer.get();
          int piece_size = piece_data.size;

          if (piece == start_piece) {
            self->socket_.set_option(
                net::socket_base::send_buffer_size(piece_size));
            buffer_start += start_offset;
            piece_size -= start_offset;
          }

          if (piece == end_piece)
            piece_size -= end_offset;

          // move piece_data.buffer to tmp to prevent its deallocation while
          // writing
          net::async_write(
              self->socket_, net::const_buffer(buffer_start, piece_size),
              [self = std::move(self), t, start_piece, end_piece, piece,
               start_offset, end_offset, keep_alive, written,
               tmp = std::move(piece_data.buffer)](
                  const boost::system::error_code &ec,
                  std::size_t transferred) {
                if (ec || piece == end_piece)
                  self->on_write(ec, written + transferred, keep_alive);
                else
                  self->do_stream(t, start_piece, end_piece,
                                  lt::piece_index_t(int(piece) + 1),
                                  start_offset, end_offset, keep_alive,
                                  written + transferred);
              });
        });

    auto buffer_pieces = std::min(
        lt::piece_index_t(int(piece) + (int(piece) - int(start_piece) + 1)),
        end_piece);
    for (lt::piece_index_t future_piece{int(piece) + 1};
         future_piece <= buffer_pieces; future_piece++) {
      if (t.have_piece(future_piece))
        continue;
      t.set_piece_deadline(future_piece, int(future_piece - piece) * 5000);
    }
  }

  void do_close() {
    boost::system::error_code ec;
    socket_.shutdown(tcp::socket::shutdown_send, ec);
  }

  void handle_get(const request &req) {
    response res{};
    res.keep_alive = req.keep_alive;
    res.headers["Connection"] = (req.keep_alive ? "keep-alive" : "close");

    if (req.target == "/torrents") {
      boost::json::array torrents;
      for (auto &t : session_->get_torrents()) {
        auto info = t.torrent_file();
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

      return do_write(res);
    }

    if (std::regex_search(req.target,
                          std::regex("^/torrents/([0-9a-fA-F]{40})$"))) {
      std::string info_hash = req.target.substr(10);

      lt::sha1_hash sha1;
      lt::aux::from_hex(info_hash, sha1.data());
      lt::torrent_handle t = session_->find_torrent(sha1);

      if (!t.is_valid()) {
        std::string content = "Torrent not found";
        res.status = 404;
        res.headers["Content-Type"] = "text/plain";
        res.headers["Content-Length"] = std::to_string(content.length());
        if (req.method == "GET")
          res.content = std::move(content);

        return do_write(res);
      }

      if (!handler_->wait_metadata(t)) {
        std::string content = "Torrent not found";
        res.status = 404;
        res.headers["Content-Type"] = "text/plain";
        res.headers["Content-Length"] = std::to_string(content.length());
        if (req.method == "GET")
          res.content = std::move(content);

        return do_write(res);
      }

      std::string content = build_playlist(wrap_files(t.torrent_file()));
      res.status = 200;
      res.headers["Content-Type"] = "application/json";
      res.headers["Content-Length"] = std::to_string(content.length());
      if (req.method == "GET")
        res.content = std::move(content);

      return do_write(res);
    }

    if (std::regex_search(req.target,
                          std::regex("^/torrents/([0-9a-fA-F]{40})/(.+)$"))) {
      std::stringstream decoded;
      decoded << boost::urls::decode_view(req.target);

      std::string info_hash = req.target.substr(10, 40);
      boost::filesystem::path path = decoded.str().substr(51);

      lt::sha1_hash sha1;
      lt::aux::from_hex(info_hash, sha1.data());
      lt::torrent_handle t = session_->find_torrent(sha1);

      if (!t.is_valid()) {
        std::string content = "Torrent not found";
        res.status = 404;
        res.headers["Content-Type"] = "text/plain";
        res.headers["Content-Length"] = std::to_string(content.length());
        if (req.method == "GET")
          res.content = std::move(content);

        return do_write(res);
      }

      if (!handler_->wait_metadata(t)) {
        std::string content = "Torrent not found";
        res.status = 404;
        res.headers["Content-Type"] = "text/plain";
        res.headers["Content-Length"] = std::to_string(content.length());
        if (req.method == "GET")
          res.content = std::move(content);

        return do_write(res);
      }

      auto info = t.torrent_file();
      lt::file_index_t file_index{-1};
      lt::file_index_t file_count{info->num_files()};
      for (lt::file_index_t i{0}; i < file_count; i++) {
        if (info->files().file_path(i) == path.make_preferred()) {
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

        return do_write(res);
      }

      int64_t size = info->files().file_size(file_index);

      range_parser::HTTPRange parsed;
      auto field = req.headers.find("Range");
      if (field == req.headers.end())
        parsed = range_parser::parse("bytes=0-", size);
      else
        parsed = range_parser::parse(field->second, size);

      range_parser::Range range = parsed.ranges.at(0);

      std::string response;
      response.reserve(256);
      response += "HTTP/1.1 ";
      response += (range.length < size ? "206" : "200");
      response += "\r\nAccept-Ranges: bytes\r\nConnection: ";
      response += (req.keep_alive ? "keep-alive" : "close");
      response += "\r\nContent-Type: ";
      response += mime_type(path.string());
      response += "\r\nContent-Length: ";
      response += std::to_string(range.length);
      if (range.length < size) {
        response += "\r\nContent-Range: ";
        response += range.content_range(size);
      }
      response += "\r\n\r\n";

      boost::system::error_code ec;
      std::size_t header_written =
          net::write(socket_, net::buffer(response), ec);

      if (req.method == "HEAD" || ec)
        return on_write(ec, header_written, req.keep_alive);

      lt::peer_request mappings = info->map_file(file_index, range.start, 0);
      lt::peer_request end_mappings =
          info->map_file(file_index, range.start + range.length, 0);

      lt::piece_index_t start_piece = mappings.piece;
      lt::piece_index_t end_piece{
          std::min(int(end_mappings.piece), int(info->num_pieces() - 1))};
      int64_t end_piece_size = info->files().piece_size(end_piece);

      int start_offset = mappings.start;
      int end_offset =
          end_mappings.start > 0 ? end_piece_size - end_mappings.start : 0;

      t.set_piece_deadline(start_piece, 5000);

      do_stream(t, start_piece, end_piece, start_piece, start_offset,
                end_offset, res.keep_alive);
      return;
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

      do_write(res);
      return token_.request_stop();
    }

    std::string content = "Forbidden";
    res.status = 403;
    res.headers["Content-Type"] = "text/plain";
    res.headers["Content-Length"] = std::to_string(content.length());
    if (req.method == "GET")
      res.content = std::move(content);

    return do_write(res);
  }

  void handle_post(const request &req) {
    std::istream request_stream(buffer_.get());
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

      return do_write(res);
    }

    lt::add_torrent_params params = get_torrent_params(body);
    params.save_path = handler_->save_path.make_preferred().string();
    lt::torrent_handle t = session_->find_torrent(params.info_hashes.v1);

    if (!t.is_valid()) {
      lt::error_code ec;
      t = session_->add_torrent(params, ec);
      if (ec) {
        std::string content = "Failed to add torrent " + ec.message();
        res.status = 400;
        res.headers["Content-Type"] = "text/plain";
        res.headers["Content-Length"] = std::to_string(content.length());
        res.content = std::move(content);

        return do_write(res);
      }
    }

    if (!handler_->wait_metadata(t)) {
      std::string content = "Torrent not found";
      res.status = 404;
      res.headers["Content-Type"] = "text/plain";
      res.headers["Content-Length"] = std::to_string(content.length());
      if (req.method == "GET")
        res.content = std::move(content);

      return do_write(res);
    }

    std::string content = build_playlist(wrap_files(t.torrent_file()));
    res.status = 200;
    res.headers["Content-Type"] = "application/vnd.apple.mpegurl";
    res.headers["Content-Length"] = std::to_string(content.length());
    res.content = std::move(content);

    return do_write(res);
  }

  void handle_delete(const request &req) {
    response res{};
    res.keep_alive = req.keep_alive;
    res.headers["Connection"] = (req.keep_alive ? "keep-alive" : "close");

    if (std::regex_search(req.target,
                          std::regex("^/torrents/([0-9a-fA-F]{40})"))) {
      std::string info_hash = req.target.substr(10, 40);

      lt::sha1_hash sha1;
      lt::aux::from_hex(info_hash, sha1.data());
      lt::torrent_handle t = session_->find_torrent(sha1);

      if (!t.is_valid()) {
        std::string content = "Torrent not found";
        res.status = 404;
        res.headers["Content-Type"] = "text/plain";
        res.headers["Content-Length"] = std::to_string(content.length());
        res.content = std::move(content);

        return do_write(res);
      }

      if (req.target.find("?DeleteFiles=true") == std::string::npos)
        session_->remove_torrent(t);
      else
        session_->remove_torrent(t, lt::remove_flags_t{(unsigned char)(1U)});

      std::string content = "Torrent successfully deleted";
      res.status = 200;
      res.headers["Content-Type"] = "text/plain";
      res.headers["Content-Length"] = std::to_string(content.length());
      res.content = std::move(content);

      return do_write(res);
    }

    std::string content = "Forbidden";
    res.status = 403;
    res.headers["Content-Type"] = "text/plain";
    res.headers["Content-Length"] = std::to_string(content.length());
    res.content = std::move(content);

    return do_write(res);
  }

  void handle_no_method(const request &req) {
    std::string content = "Method not allowed";
    response res{};
    res.keep_alive = req.keep_alive;
    res.status = 405;
    res.headers["Connection"] = (req.keep_alive ? "keep-alive" : "close");
    res.headers["Content-Type"] = "text/plain";
    res.headers["Content-Length"] = std::to_string(content.length());
    res.content = std::move(content);

    return do_write(res);
  }

  std::string
  build_playlist(const boost::container::flat_set<wrapped_file> &wf) {
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
    boost::container::flat_set<wrapped_file> files = wrap_files(info);

    return wrapped_torrent{info->name(),
                           lt::aux::to_hex(info->info_hashes().v1), files,
                           info->total_size(), build_playlist(files)};
  }

  boost::container::flat_set<wrapped_file>
  wrap_files(std::shared_ptr<const lt::torrent_info> info) {
    int n = info->num_files();

    boost::container::flat_set<wrapped_file> files;

    std::string address = getLocalIp();
    std::string port = std::to_string(socket_.local_endpoint().port());

    for (lt::file_index_t i{0}; i < lt::file_index_t(n); i++) {
      std::string path = info->files().file_path(i);
      std::replace(path.begin(), path.end(), '\\', '/');

      std::size_t pos = path.rfind("/") + 1;
      int depth = 0;
      for (std::size_t c = 0; c < path.length(); c++)
        if (path[c] == '/')
          depth++;

      auto iter = files.emplace(
          path.substr(pos),
          "http://" + address + ":" + port + "/torrents/" +
              lt::aux::to_hex(info->info_hashes().v1) + "/" + path,
          info->files().file_size(i), mime_type(path), depth);
    }

    return files;
  }
};

class torrent_server {
  net::thread_pool::executor_type ex_;
  tcp::acceptor acceptor_;
  std::shared_ptr<handler::alert_handler> handler_;
  net::signal_set signals_;
  stop_token token_;

public:
  torrent_server(net::thread_pool::executor_type ex, tcp::endpoint endpoint,
                 std::shared_ptr<handler::alert_handler> handler)
      : ex_(ex), acceptor_(net::make_strand(ex), endpoint), handler_(handler),
        signals_(ex, SIGINT, SIGTERM) {
    signals_.async_wait([this](boost::system::error_code ec, int) {
      if (!ec)
        token_.request_stop();
    });
    token_.add_callback([this]() {
      signals_.cancel();
      acceptor_.cancel();
      handler_->stop();
    });
    do_accept();
  }

  ~torrent_server() { token_.wait_stop(); }

private:
  void do_accept() {
    acceptor_.async_accept(
        net::make_strand(ex_),
        [this](const boost::system::error_code &ec, tcp::socket socket) {
          if (!ec)
            std::make_shared<http_session>(std::move(socket), handler_, token_)
                ->run();
          else if (ec == net::error::operation_aborted) {
            std::cout << "Accept loop exiting...\n";
            return;
          } else
            fail(ec, "accept");

          do_accept();
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
      "save-path", po::value<fs::path>()->default_value("."),
      "Directory where downloaded files are stored");

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  auto const address =
      net::ip::make_address(vm.at("address").as<std::string>());
  auto const port = vm.at("port").as<uint16_t>();
  auto const save_path = vm.at("save-path").as<fs::path>();

  auto const resume_path = save_path / "resume_data";

  if (!(fs::exists(save_path) && fs::is_directory(save_path))) {
    std::cerr << "Invalid save path '" << save_path << "'\n";
    return 1;
  }

  net::thread_pool pool(std::thread::hardware_concurrency());
  lt::session_params params;
  params.settings.set_int(lt::settings_pack::alert_mask,
                          lt::alert_category::status |
                              lt::alert_category::storage |
                              lt::alert_category::piece_progress);
  params.settings.set_int(lt::settings_pack::connection_speed, 500);
  params.settings.set_int(lt::settings_pack::connections_limit, 800);
  params.settings.set_int(lt::settings_pack::listen_queue_size, 50);
  params.settings.set_int(lt::settings_pack::max_queued_disk_bytes,
                          7 * 1024 * 1024);
  params.settings.set_int(lt::settings_pack::max_rejects, 10);
  params.settings.set_int(lt::settings_pack::mixed_mode_algorithm,
                          lt::settings_pack::prefer_tcp);
  params.settings.set_int(lt::settings_pack::request_timeout, 10);
  params.settings.set_int(lt::settings_pack::smooth_connects, false);
  params.settings.set_int(lt::settings_pack::torrent_connect_boost, 100);
  params.settings.set_bool(lt::settings_pack::close_redundant_connections,
                           false);
  params.settings.set_bool(lt::settings_pack::no_atime_storage, true);
  auto handler = std::make_shared<handler::alert_handler>(params, save_path);

  if (!fs::exists(resume_path))
    fs::create_directory(resume_path);

  for (auto &entry : fs::directory_iterator(resume_path)) {
    if (entry.path().extension() != ".fastresume")
      continue;
    auto params = get_torrent_params(entry.path().string());
    params.save_path = handler->save_path.make_preferred().string();
    handler->session->async_add_torrent(params);
  }

  torrent_server server(pool.get_executor(), tcp::endpoint{address, port},
                        handler);
  std::cout << "Server running on port " << port << "...\n";

  pool.join();
  handler->join();

  std::cout << "Closing program...\n";

  return 0;
}
