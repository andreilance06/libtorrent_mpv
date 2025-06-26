#include "alert_handler.hpp"
#include "libusockets.h"
#include "range_parser.hpp"
#include "wrappers.hpp"
#include <App.h>
#include <boost/program_options.hpp>
#include <boost/url/decode_view.hpp>
#include <filesystem>
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
#include <string_view>

static lt::add_torrent_params get_torrent_params(std::string_view id) {
  lt::add_torrent_params params;
  lt::error_code ec;

  auto const pos = id.rfind('.');
  std::string_view ext;
  if (pos == std::string_view::npos)
    ext = std::string_view{};
  else
    ext = id.substr(pos);

  if (ext == ".fastresume") {
    std::ifstream in(std::string(id), std::ios_base::binary);
    std::vector<char> buf(std::istreambuf_iterator<char>(in), {});
    return lt::read_resume_data(buf, ec);
  }

  params.ti = std::make_shared<lt::torrent_info>(std::string(id), ec);
  if (!ec)
    return params;

  params = lt::parse_magnet_uri(lt::string_view(id.data(), id.size()), ec);
  if (!ec)
    return params;

  static const std::regex infohash_regex("^([0-9a-fA-F]{40})$");
  if (std::regex_search(id.begin(), id.end(), infohash_regex)) {
    lt::sha1_hash sha1;
    lt::aux::from_hex(id, sha1.data());
    params.info_hashes.v1 = sha1;
    return params;
  }

  return lt::add_torrent_params{};
}

int main(int argc, char **argv) {
  namespace po = boost::program_options;
  namespace fs = std::filesystem;

  po::options_description desc("Allowed options");
  desc.add_options()("help", "produce help")(
      "address", po::value<std::string>()->default_value("0.0.0.0"),
      "HTTP server address")("port", po::value<uint16_t>()->default_value(1337),
                             "HTTP server port")(
      "save-path", po::value<fs::path>()->default_value(""),
      "Directory where downloaded files are stored");

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  auto const address = vm.at("address").as<std::string>();
  auto const port = vm.at("port").as<uint16_t>();
  auto const save_path = vm.at("save-path").as<fs::path>();
  auto const resume_path = save_path / "resume_data";

  if (!(fs::exists(save_path) && fs::is_directory(save_path))) {
    std::cerr << "Invalid save path '" << save_path << "'\n";
    return 1;
  }

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
  params.settings.set_int(lt::settings_pack::torrent_connect_boost, 100);
  params.settings.set_int(lt::settings_pack::unchoke_slots_limit, -1);
  params.settings.set_bool(lt::settings_pack::no_atime_storage, true);
  params.settings.set_bool(lt::settings_pack::smooth_connects, false);
  auto handler = std::make_shared<alert_handler::handler>(params, save_path);

  if (!fs::exists(resume_path))
    fs::create_directory(resume_path);

  for (auto &entry : fs::directory_iterator(resume_path)) {
    if (entry.path().extension() != ".fastresume")
      continue;
    auto params = get_torrent_params(entry.path().string());
    params.save_path = handler->save_path.make_preferred().string();
    handler->session->async_add_torrent(params);
  }

  us_listen_socket_t *listen_socket = nullptr;
  auto loop = uWS::Loop::get();
  uWS::App()
      .get("/torrents",
           [=](auto *res, auto *req) {
             boost::json::array torrents;
             for (auto &t : handler->session->get_torrents()) {
               auto info = t.torrent_file();
               if (info == nullptr)
                 continue;

               auto wt = wrappers::wrap_torrent(info);
               boost::json::value data = wrappers::to_json(wt);
               torrents.push_back(data);
             }

             std::string content = boost::json::serialize(torrents);
             res->writeHeader("Content-Type", "application/json");
             res->end(content);
           })
      .get("/torrents/:infohash",
           [=](auto *res, auto *req) {
             std::string_view info_hash = req->getParameter(0);

             lt::sha1_hash sha1;
             lt::aux::from_hex(info_hash, sha1.data());
             lt::torrent_handle t = handler->session->find_torrent(sha1);

             if (!t.is_valid()) {
               res->writeStatus("404 Not Found");
               res->end("Torrent not found");
               return;
             }

             auto aborted = std::make_shared<std::atomic<bool>>(false);
             res->onAborted([aborted]() { aborted->store(true); });
             handler->wait_metadata(
                 t, [=](const std::shared_ptr<const lt::torrent_info> &info) {
                   if (aborted->load())
                     return;

                   if (!info) {
                     loop->defer([=]() {
                       res->writeStatus("404 Not Found");
                       res->end("Torrent not found");
                     });
                     return;
                   }

                   std::string content =
                       wrappers::build_playlist(wrappers::wrap_files(info));
                   loop->defer([=]() {
                     res->writeHeader("Content-Type",
                                      "application/vnd.apple.mpegurl");
                     res->end(content);
                   });
                 });
           })
      .get(
          "/torrents/:infohash/*",
          [=](auto *res, auto *req) {
            std::string_view info_hash = req->getParameter(0);
            boost::urls::decode_view decoded(req->getUrl());
            std::filesystem::path path =
                std::string(decoded.begin(), decoded.end()).substr(51);
            path = path.make_preferred();

            lt::sha1_hash sha1;
            lt::aux::from_hex(info_hash, sha1.data());
            lt::torrent_handle t = handler->session->find_torrent(sha1);

            if (!t.is_valid()) {
              res->writeStatus("404 Not Found");
              res->end("Torrent not found");
              return;
            }
            auto aborted = std::make_shared<std::atomic<bool>>(false);
            res->onAborted([aborted]() { aborted->store(true); });
            handler->wait_metadata(
                t, [=](const std::shared_ptr<const lt::torrent_info> &info) {
                  if (aborted->load())
                    return;

                  if (!info) {
                    loop->defer([=]() {
                      res->writeStatus("404 Not Found");
                      res->end("Torrent not found");
                    });
                    return;
                  }
                  lt::file_index_t file_index{-1};
                  lt::file_index_t file_count{info->num_files()};
                  for (lt::file_index_t i{0}; i < file_count; i++) {
                    if (info->files().file_path(i) == path.string()) {
                      file_index = i;
                      break;
                    }
                  }
                  if (file_index < lt::file_index_t(0)) {
                    loop->defer([=]() {
                      res->writeStatus("404 Not Found");
                      res->end("File not found");
                    });
                    return;
                  }
                  int64_t size = info->files().file_size(file_index);
                  // Parse Range header
                  std::string range_header;
                  if (req->getHeader("range").length() > 0)
                    range_header = std::string(req->getHeader("range"));
                  else
                    range_header = "bytes=0-";
                  range_parser::HTTPRange parsed =
                      range_parser::parse(range_header, size);
                  range_parser::Range range = parsed.ranges.at(0);
                  std::string status =
                      (range.length < size) ? "206 Partial Content" : "200 OK";
                  loop->defer([=]() {
                    res->writeStatus(status);
                    res->writeHeader("Accept-Ranges", "bytes");
                    res->writeHeader("Content-Type",
                                     wrappers::mime_type(path.string()));
                    if (range.length < size) {
                      res->writeHeader("Content-Range",
                                       range.content_range(size));
                    }
                  });

                  // Streaming logic
                  lt::peer_request mappings =
                      info->map_file(file_index, range.start, 0);
                  lt::peer_request end_mappings =
                      info->map_file(file_index, range.start + range.length, 0);
                  lt::piece_index_t start_piece = mappings.piece;
                  lt::piece_index_t end_piece = lt::piece_index_t(std::min(
                      int(end_mappings.piece), int(info->num_pieces() - 1)));
                  int64_t end_piece_size = info->files().piece_size(end_piece);
                  int start_offset = mappings.start;
                  int end_offset = end_mappings.start > 0
                                       ? end_piece_size - end_mappings.start
                                       : 0;
                  // Helper lambda for streaming

                  auto stream_piece = std::make_shared<
                      std::function<void(lt::piece_index_t, std::size_t)>>();
                  *stream_piece = ([=](lt::piece_index_t piece,
                                       std::size_t written) {
                    if (aborted->load())
                      return;

                    handler->schedule_piece(
                        t, piece, [=](const piece_entry &piece_data) {
                          if (aborted->load())
                            return;
                          if (piece_data.buffer == nullptr) {
                            loop->defer(
                                [=]() { res->tryEnd({}, range.length); });
                            return;
                          }

                          char *buffer_start = piece_data.buffer.get();
                          int piece_size = piece_data.size;
                          if (piece == start_piece) {
                            buffer_start += start_offset;
                            piece_size -= start_offset;
                          }
                          if (piece == end_piece)
                            piece_size -= end_offset;

                          loop->defer([=]() {
                            auto [ok, done] = res->tryEnd(
                                std::string_view(buffer_start, piece_size),
                                range.length);
                            if (done) {
                              return;
                            }

                            if (!ok) {
                              res->onWritable([=, buf = piece_data.buffer](
                                                  std::size_t offset) {
                                auto mapping = info->map_file(
                                    file_index, range.start + offset, 0);

                                auto new_start = buffer_start + mapping.start;
                                auto new_size = piece_size - mapping.start;
                                if (piece == start_piece) {
                                  new_start -= start_offset;
                                  new_size += start_offset;
                                }

                                auto [ok2, done2] = res->tryEnd(
                                    std::string_view(new_start, new_size),
                                    range.length);

                                if (done2) {
                                  return true;
                                }

                                if (!ok2) {
                                  return false;
                                }

                                if (piece != end_piece) {
                                  // Continue streaming next piece
                                  (*stream_piece)(
                                      lt::piece_index_t(int(piece) + 1),
                                      written + piece_size);
                                }

                                return true;
                              });

                              return;
                            }

                            if (piece != end_piece) {
                              (*stream_piece)(lt::piece_index_t(int(piece) + 1),
                                              written + piece_size);
                            }
                          });
                        });

                    auto buffer_pieces = std::min(
                        lt::piece_index_t(int(piece) +
                                          (int(piece) - int(start_piece) + 1)),
                        end_piece);
                    for (lt::piece_index_t future_piece{int(piece) + 1};
                         future_piece <= buffer_pieces; future_piece++) {
                      if (!t.is_valid() || t.have_piece(future_piece))
                        continue;
                      t.set_piece_deadline(future_piece,
                                           int(future_piece - piece) * 5000);
                    }
                  });
                  // Start streaming
                  if (!t.have_piece(start_piece))
                    t.set_piece_deadline(start_piece, 5000);
                  (*stream_piece)(start_piece, 0);
                });
          })
      .post("/torrents",
            [=](auto *res, auto *req) {
              res->onData([=](std::string_view body, bool) {
                lt::add_torrent_params params = get_torrent_params(body);
                params.save_path = handler->save_path.make_preferred().string();
                lt::torrent_handle t =
                    handler->session->find_torrent(params.info_hashes.v1);

                if (!t.is_valid()) {
                  lt::error_code ec;
                  t = handler->session->add_torrent(params, ec);
                  if (ec) {
                    res->writeStatus("400 Bad Request");
                    res->end("Failed to add torrent " + ec.message());
                    return;
                  }
                }

                auto aborted = std::make_shared<std::atomic<bool>>(false);
                res->onAborted([aborted]() { aborted->store(true); });
                handler->wait_metadata(
                    t,
                    [=](const std::shared_ptr<const lt::torrent_info> &info) {
                      if (aborted->load())
                        return;

                      if (!info) {
                        loop->defer([=]() {
                          res->writeStatus("404 Not Found");
                          res->end("Torrent not found");
                        });
                        return;
                      }

                      std::string content =
                          wrappers::build_playlist(wrappers::wrap_files(info));
                      loop->defer([=]() {
                        res->writeHeader("Content-Type",
                                         "application/vnd.apple.mpegurl");
                        res->end(content);
                      });
                    });
              });
            })
      .del("/torrents/:infohash",
           [=](auto *res, auto *req) {
             std::string_view info_hash = req->getParameter(0);

             lt::sha1_hash sha1;
             lt::aux::from_hex(info_hash, sha1.data());
             lt::torrent_handle t = handler->session->find_torrent(sha1);

             if (!t.is_valid()) {
               res->writeStatus("404 Not Found");
               res->end("Torrent not found");
               return;
             }

             if (req->getQuery("DeleteFiles") == "true")
               handler->session->remove_torrent(
                   t, lt::remove_flags_t{(unsigned char)(1U)});
             else
               handler->session->remove_torrent(t);

             res->end("Torrent successfully deleted");
           })
      .get("/shutdown",
           [&listen_socket](auto *res, auto *req) {
             res->end("Server shutting down...");
             us_listen_socket_close(0, listen_socket);
           })
      .any("/*",
           [](auto *res, auto *req) {
             res->writeStatus("403 Forbidden");
             res->end("Forbidden");
           })
      .listen(address, port,
              [=, &listen_socket](auto *token) {
                if (token) {
                  listen_socket = token;
                  std::cout << "Server running on port " << port << "...\n";
                } else {
                  std::cerr << "Failed to listen on port " << port << "\n";
                }
              })
      .run();

  std::cout << "Shutting down server...\n";
  handler->stop();
  handler->join();
  std::cout << "Closing program...\n";
  return 0;
}
