#include <boost/core/ignore_unused.hpp>
#include <boost/filesystem.hpp>
#include <fstream>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/hex.hpp>
#include <libtorrent/session.hpp>
#include <libtorrent/write_resume_data.hpp>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include <iostream>

#include "alert_handler.hpp"

using namespace handler;
namespace fs = boost::filesystem;

alert_handler::alert_handler(lt::session_params params,
                             boost::filesystem::path save_path)
    : session(std::make_shared<lt::session>(params)), save_path(save_path) {

  alert_thread_ = std::thread([this] {
    auto temp_ptr = session;
    std::vector<lt::alert *> alerts;
    for (;;) {
      alerts.clear();
      if (temp_ptr.unique() && outstanding_saves_ == 0)
        break;

      temp_ptr->pop_alerts(&alerts);
      for (auto a : alerts)
        handle_alert(a);

      temp_ptr->wait_for_alert(std::chrono::seconds(1));
    }

    std::cout << "Alert handler exiting...\n";
  });
}

void alert_handler::handle_alert(lt::alert *a) {

  switch (a->type()) {
  case lt::read_piece_alert::alert_type:
    handle_read_piece_alert(lt::alert_cast<lt::read_piece_alert>(a));
    break;
  case lt::piece_finished_alert::alert_type:
    handle_piece_finished_alert(lt::alert_cast<lt::piece_finished_alert>(a));
    break;
  case lt::add_torrent_alert::alert_type:
    handle_add_torrent_alert(lt::alert_cast<lt::add_torrent_alert>(a));
    break;
  case lt::metadata_received_alert::alert_type:
    handle_metadata_received_alert(
        lt::alert_cast<lt::metadata_received_alert>(a));
    break;
  case lt::torrent_removed_alert::alert_type:
    handle_torrent_removed_alert(lt::alert_cast<lt::torrent_removed_alert>(a));
    break;
  case lt::save_resume_data_alert::alert_type:
    handle_save_resume_data_alert(
        lt::alert_cast<lt::save_resume_data_alert>(a));
    break;
  case lt::save_resume_data_failed_alert::alert_type:
    handle_save_resume_data_failed_alert(
        lt::alert_cast<lt::save_resume_data_failed_alert>(a));
    break;
  case lt::torrent_finished_alert::alert_type:
    handle_torrent_finished_alert(
        lt::alert_cast<lt::torrent_finished_alert>(a));
    break;
  }
}

void alert_handler::handle_read_piece_alert(lt::read_piece_alert *a) {

  std::unique_lock<std::shared_mutex> l(piece_requests_mtx_);

  auto [start, end] = piece_requests_.equal_range(
      piece_request{a->handle.info_hashes(), a->piece});

  if (start == end)
    return;

  for (auto i = start; i != end; i++)
    i->callback(piece_entry{a->piece, a->buffer, a->size});

  piece_requests_.erase(start, end);
  l.unlock();
}

void alert_handler::handle_piece_finished_alert(lt::piece_finished_alert *a) {
  lt::torrent_handle t = a->handle;

  std::shared_lock<std::shared_mutex> l(piece_requests_mtx_);
  if (piece_requests_.find(piece_request{t.info_hashes(), a->piece_index}) ==
      piece_requests_.end())
    return;
  l.unlock();

  t.read_piece(a->piece_index);
}

void alert_handler::handle_add_torrent_alert(lt::add_torrent_alert *a) {
  if (a->error)
    return;

  lt::torrent_handle t = a->handle;
  if (t.torrent_file() == nullptr)
    return;

  auto resume_file = save_path / "resume_data" /
                     (lt::aux::to_hex(t.info_hashes().v1) + ".fastresume");

  if (fs::exists(resume_file) && fs::is_regular_file(resume_file))
    return;

  lt::piece_index_t piece_count{t.torrent_file()->num_pieces()};
  std::vector<std::pair<lt::piece_index_t, lt::download_priority_t>> priorities;
  priorities.reserve(int(piece_count));
  for (lt::piece_index_t i{0}; i < piece_count; i++)
    priorities.push_back(std::pair<lt::piece_index_t, lt::download_priority_t>(
        i, lt::dont_download));
  t.prioritize_pieces(priorities);

  t.save_resume_data(t.only_if_modified | t.save_info_dict);
}

void alert_handler::handle_metadata_received_alert(
    lt::metadata_received_alert *a) {
  lt::torrent_handle t = a->handle;
  auto info = t.torrent_file();

  std::unique_lock<std::mutex> l(torrent_requests_mtx_);
  auto [start, end] =
      torrent_requests_.equal_range(torrent_request{t.info_hashes()});

  if (start != end) {
    for (auto i = start; i != end; i++)
      i->callback(info);
  }
  torrent_requests_.erase(start, end);
  l.unlock();

  lt::piece_index_t piece_count{info->num_pieces()};
  std::vector<std::pair<lt::piece_index_t, lt::download_priority_t>> priorities;
  priorities.reserve(int(piece_count));
  for (lt::piece_index_t i{0}; i < piece_count; i++)
    priorities.push_back(std::pair<lt::piece_index_t, lt::download_priority_t>(
        i, lt::dont_download));
  t.prioritize_pieces(priorities);
}

void alert_handler::handle_torrent_removed_alert(lt::torrent_removed_alert *a) {
  std::unique_lock<std::shared_mutex> l1(piece_requests_mtx_);
  piece_request search_key{a->info_hashes, lt::piece_index_t{0}};
  auto first = piece_requests_.lower_bound(search_key);

  search_key.piece = lt::piece_index_t{INT_MAX};
  auto last = piece_requests_.upper_bound(search_key);

  for (auto i = first; i != last; i++)
    i->callback({});
  piece_requests_.erase(first, last);
  l1.unlock();

  std::unique_lock<std::mutex> l2(torrent_requests_mtx_);
  auto [start, end] =
      torrent_requests_.equal_range(torrent_request{a->info_hashes});
  for (auto i = start; i != end; i++)
    i->callback({});
  torrent_requests_.erase(start, end);
  l2.unlock();

  boost::system::error_code ec;
  fs::remove(save_path / "resume_data" /
                 (lt::aux::to_hex(a->info_hashes.v1) + ".fastresume"),
             ec);
}

void alert_handler::handle_save_resume_data_alert(
    lt::save_resume_data_alert *a) {
  auto path = save_path / "resume_data" /
              (lt::aux::to_hex(a->handle.info_hashes().v1) + ".fastresume");
  auto tmp_path =
      save_path / "resume_data" / lt::aux::to_hex(a->handle.info_hashes().v1);

  std::ofstream tmp(tmp_path.c_str(),
                    std::ios_base::binary | std::ios_base::trunc);
  std::vector<char> buf = lt::write_resume_data_buf(a->params);
  tmp.write(buf.data(), buf.size());
  tmp.close();

  boost::system::error_code ec;
  fs::rename(tmp_path, path, ec);
  if (outstanding_saves_)
    outstanding_saves_--;
}

void alert_handler::handle_save_resume_data_failed_alert(
    lt::save_resume_data_failed_alert *a) {
  boost::ignore_unused(a);
  if (outstanding_saves_)
    outstanding_saves_--;
}

void alert_handler::handle_torrent_finished_alert(
    lt::torrent_finished_alert *a) {
  lt::torrent_handle t = a->handle;

  t.save_resume_data(t.only_if_modified | t.save_info_dict);
}

void alert_handler::schedule_piece(const lt::torrent_handle &t,
                                   lt::piece_index_t const piece,
                                   std::function<void(piece_entry)> callback) {

  if (session == nullptr || !t.is_valid() || !t.in_session())
    return callback({});

  std::unique_lock<std::shared_mutex> l(piece_requests_mtx_);
  piece_requests_.emplace(t.info_hashes(), piece, callback);
  l.unlock();
  if (t.have_piece(piece))
    t.read_piece(piece);
}

void alert_handler::wait_metadata(
    const lt::torrent_handle &t,
    std::function<void(std::shared_ptr<const lt::torrent_info>)> callback) {
  if (session == nullptr || !t.is_valid() || !t.in_session())
    return callback({});

  if (auto info = t.torrent_file(); info != nullptr)
    return callback(info);

  std::lock_guard<std::mutex> l(torrent_requests_mtx_);
  torrent_requests_.emplace(t.info_hashes(), callback);
}

void alert_handler::join() { alert_thread_.join(); }

void alert_handler::stop() {
  std::unique_lock<std::shared_mutex> l1(piece_requests_mtx_);
  std::lock_guard<std::mutex> l2(torrent_requests_mtx_);
  for (auto &t : session->get_torrents()) {
    if (t.torrent_file() == nullptr)
      continue;

    outstanding_saves_++;
    t.save_resume_data(t.only_if_modified | t.save_info_dict);
  }
  session.reset();
  for (auto req : torrent_requests_)
    req.callback({});
  torrent_requests_.clear();
  for (auto req : piece_requests_)
    req.callback({});
  piece_requests_.clear();
}