#include "wrappers.hpp"
#include <boost/range/algorithm/replace.hpp>
#include <libtorrent/hex.hpp>

namespace wrappers {
std::string_view mime_type(std::string_view path) {
  static const std::unordered_map<std::string_view, std::string_view>
      mime_types = {{".htm", "text/html"},
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

  auto const pos = path.rfind('.');
  if (pos == std::string_view::npos)
    return "application/octet-stream";

  std::string_view ext = path.substr(pos);
  auto it = mime_types.find(ext);
  if (it != mime_types.end()) {
    return it->second;
  }

  return "application/octet-stream";
}

boost::json::value to_json(const wrappers::wrapped_file &file) {
  return {{"Name", file.Name},
          {"Path", file.Path},
          {"Length", file.Length},
          {"MimeType", file.MimeType},
          {"depth", file.depth}};
}

boost::json::value to_json(const wrappers::wrapped_torrent &torrent) {
  boost::json::array files_json;
  for (const wrappers::wrapped_file &file : torrent.Files) {
    files_json.push_back(wrappers::to_json(file));
  }

  return {{"Name", torrent.Name},
          {"InfoHash", torrent.InfoHash},
          {"Files", files_json},
          {"Length", torrent.Length}};
}

boost::container::flat_set<wrappers::wrapped_file>
wrap_files(std::shared_ptr<const lt::torrent_info> info) {

  int n = info->num_files();
  boost::container::flat_set<wrappers::wrapped_file> files;

  for (lt::file_index_t i{0}; i < lt::file_index_t(n); i++) {
    std::string path = info->files().file_path(i);
    boost::range::replace(path, '\\', '/');

    std::size_t pos = path.rfind('/') + 1;
    int depth = 0;
    for (std::size_t c = 0; c < path.length(); c++)
      if (path[c] == '/')
        depth++;

    files.emplace(path.substr(pos),
                  lt::aux::to_hex(info->info_hashes().v1) + "/" + path,
                  info->files().file_size(i), mime_type(path), depth);
  }

  return files;
}

wrappers::wrapped_torrent
wrap_torrent(std::shared_ptr<const lt::torrent_info> info) {

  boost::container::flat_set<wrappers::wrapped_file> files = wrap_files(info);

  return wrappers::wrapped_torrent{info->name(),
                                   lt::aux::to_hex(info->info_hashes().v1),
                                   files, info->total_size()};
}

std::string build_playlist(
    const boost::container::flat_set<wrappers::wrapped_file> &files) {
  std::string playlist;

  playlist.append("#EXTM3U\n");
  for (auto &f : files) {
    if (f.MimeType.find("video") == std::string_view::npos)
      continue;
    playlist.append("#EXTINF:0," + f.Name + "\n");
    playlist.append(f.Path + "\n");
  }

  return playlist;
}
} // namespace wrappers