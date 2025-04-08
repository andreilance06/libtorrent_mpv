#include <boost/filesystem.hpp>
#include <fstream>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/hex.hpp>
#include <libtorrent/session.hpp>
#include <libtorrent/write_resume_data.hpp>
#include <mutex>
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
    for (;;) {
      if (temp_ptr.unique() && outstanding_saves_ == 0)
        break;

      std::vector<lt::alert *> alerts;
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

  std::lock_guard<std::mutex> l(requests_mtx_);

  auto range =
      requests_.equal_range(piece_request{a->handle.info_hashes(), a->piece});

  if (range.first == range.second)
    return;

  for (auto i = range.first; i != range.second; i++)
    i->callback(piece_entry{a->piece, a->buffer, a->size});

  requests_.erase(range.first, range.second);
}

void alert_handler::handle_piece_finished_alert(lt::piece_finished_alert *a) {
  lt::torrent_handle t = a->handle;

  std::lock_guard<std::mutex> l(requests_mtx_);
  if (requests_.find(piece_request{t.info_hashes(), a->piece_index}) ==
      requests_.end())
    return;

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
  for (lt::piece_index_t i{0}; i < piece_count; i++)
    priorities.push_back(std::pair<lt::piece_index_t, lt::download_priority_t>(
        i, lt::dont_download));
  t.prioritize_pieces(priorities);

  t.save_resume_data(t.only_if_modified | t.save_info_dict);
}

void alert_handler::handle_metadata_received_alert(
    lt::metadata_received_alert *a) {
  lt::torrent_handle t = a->handle;

  std::lock_guard<std::mutex> l(torrent_mtx_);
  torrent_cv_.notify_all();

  lt::piece_index_t piece_count{t.torrent_file()->num_pieces()};
  std::vector<std::pair<lt::piece_index_t, lt::download_priority_t>> priorities;
  for (lt::piece_index_t i{0}; i < piece_count; i++)
    priorities.push_back(std::pair<lt::piece_index_t, lt::download_priority_t>(
        i, lt::dont_download));
  t.prioritize_pieces(priorities);
}

void alert_handler::handle_torrent_removed_alert(lt::torrent_removed_alert *a) {

  typedef requests_t::iterator iter;

  std::lock_guard<std::mutex> l(requests_mtx_);

  piece_request search_key{a->info_hashes, lt::piece_index_t{0}};
  iter first = requests_.lower_bound(search_key);

  search_key.piece = lt::piece_index_t{INT_MAX};
  iter last = requests_.upper_bound(search_key);

  requests_.erase(first, last);

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
  if (outstanding_saves_)
    outstanding_saves_--;
}

void alert_handler::handle_torrent_finished_alert(
    lt::torrent_finished_alert *a) {
  lt::torrent_handle t = a->handle;

  t.save_resume_data(t.only_if_modified | t.save_info_dict);
}

void alert_handler::schedule_piece(lt::torrent_handle &t,
                                   lt::piece_index_t const piece,
                                   std::function<void(piece_entry)> callback) {

  std::lock_guard<std::mutex> l(requests_mtx_);

  auto entry = requests_.emplace(t.info_hashes(), piece, callback);

  if (session == nullptr) {
    entry->callback(piece_entry{});
    requests_.erase(entry);
  } else if (t.have_piece(piece))
    t.read_piece(piece);
}

bool alert_handler::wait_metadata(lt::torrent_handle &t) {
  if (session == nullptr)
    return false;

  if (t.torrent_file() == nullptr) {
    std::unique_lock<std::mutex> l(torrent_mtx_);
    torrent_cv_.wait_for(l, std::chrono::seconds(30), [this, &t]() {
      return t.torrent_file() != nullptr || session == nullptr;
    });
    return session != nullptr;
  }

  return true;
}

void alert_handler::join() { alert_thread_.join(); }

void alert_handler::stop() {
  std::lock_guard<std::mutex> l1(requests_mtx_);
  std::lock_guard<std::mutex> l2(torrent_mtx_);
  for (auto &t : session->get_torrents()) {
    if (t.torrent_file() == nullptr)
      continue;

    outstanding_saves_++;
    t.save_resume_data(t.only_if_modified | t.save_info_dict);
  }
  session.reset();
  torrent_cv_.notify_all();
  for (auto req : requests_)
    req.callback(piece_entry{});
  requests_.clear();
}