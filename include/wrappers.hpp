#pragma once

#include <boost/container/flat_set.hpp>
#include <boost/json.hpp>
#include <libtorrent/torrent_info.hpp>
#include <string>
#include <string_view>

namespace wrappers {

struct wrapped_file {
  std::string Name;
  std::string URL;
  int64_t Length;
  std::string_view MimeType;
  int depth;

  wrapped_file(std::string_view name, std::string_view url, int64_t length,
               std::string_view mime, int d)
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

// JSON conversion functions
boost::json::value to_json(const wrapped_file &file);
boost::json::value to_json(const wrapped_torrent &torrent);

std::string_view mime_type(std::string_view path);

boost::container::flat_set<wrapped_file>
wrap_files(std::shared_ptr<const lt::torrent_info> info,
           const std::string &address, uint16_t port);

wrapped_torrent wrap_torrent(std::shared_ptr<const lt::torrent_info> info,
                             const std::string &address, uint16_t port);

std::string
build_playlist(const boost::container::flat_set<wrapped_file> &files);

} // namespace wrappers