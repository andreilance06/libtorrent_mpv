#ifndef ALERT_HANDLER
#define ALERT_HANDLER

#include <boost/filesystem.hpp>
#include <condition_variable>
#include <future>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/hex.hpp>
#include <libtorrent/session.hpp>
#include <mutex>
#include <shared_mutex>

struct piece_entry {
  lt::piece_index_t piece;
  boost::shared_array<char> buffer;
  int size;
};

struct piece_request {
  lt::info_hash_t info_hash;
  lt::piece_index_t piece;
  std::function<void(piece_entry)> callback;

  piece_request(lt::info_hash_t info, lt::piece_index_t p,
                std::function<void(piece_entry)> callback)
      : info_hash(info), piece(p), callback(callback) {}

  piece_request(lt::info_hash_t info, lt::piece_index_t p)
      : info_hash(info), piece(p) {}

  inline bool operator==(piece_request const &rq) const {
    return rq.info_hash == info_hash && rq.piece == piece;
  }

  inline bool operator<(piece_request const &rq) const {
    return info_hash == rq.info_hash ? piece < rq.piece
                                     : info_hash < rq.info_hash;
  }
};

struct torrent_request {
  lt::info_hash_t info_hash;
  std::function<void(std::shared_ptr<const lt::torrent_info>)> callback;

  torrent_request(
      lt::info_hash_t info,
      std::function<void(std::shared_ptr<const lt::torrent_info>)> callback)
      : info_hash(info), callback(callback) {}

  torrent_request(lt::info_hash_t info)
      : info_hash(info) {}

  inline bool operator==(torrent_request const &rq) const {
    return rq.info_hash == info_hash;
  }

  inline bool operator<(torrent_request const &rq) const {
    return info_hash < rq.info_hash;
  }
};

namespace handler {
class alert_handler {

public:
  std::shared_ptr<lt::session> session;
  boost::filesystem::path save_path;

  alert_handler(lt::session_params params, boost::filesystem::path save_path);

  void schedule_piece(const lt::torrent_handle &t,
                      lt::piece_index_t const piece,
                      std::function<void(piece_entry)> callback);

  void wait_metadata(
      const lt::torrent_handle &t,
      std::function<void(std::shared_ptr<const lt::torrent_info>)> callback);

  void join();

  void stop();

private:
  std::thread alert_thread_;

  typedef std::multiset<piece_request> piece_req_t;
  std::shared_mutex piece_requests_mtx_;
  piece_req_t piece_requests_;

  typedef std::multiset<torrent_request> torrent_req_t;
  std::mutex torrent_requests_mtx_;
  torrent_req_t torrent_requests_;

  std::atomic_uint outstanding_saves_{0};

  void handle_alert(lt::alert *a);

  void handle_read_piece_alert(lt::read_piece_alert *a);

  void handle_piece_finished_alert(lt::piece_finished_alert *a);

  void handle_add_torrent_alert(lt::add_torrent_alert *a);

  void handle_metadata_received_alert(lt::metadata_received_alert *a);

  void handle_torrent_removed_alert(lt::torrent_removed_alert *a);

  void handle_save_resume_data_alert(lt::save_resume_data_alert *a);

  void
  handle_save_resume_data_failed_alert(lt::save_resume_data_failed_alert *a);

  void handle_torrent_finished_alert(lt::torrent_finished_alert *a);
};
} // namespace handler

#endif