#ifndef ALERT_HANDLER
#define ALERT_HANDLER

#include <boost/filesystem.hpp>
#include <condition_variable>
#include <future>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/hex.hpp>
#include <libtorrent/session.hpp>
#include <mutex>

struct piece_entry {
  lt::piece_index_t piece;
  boost::shared_array<char> buffer;
  int size;
};

struct piece_request {
  lt::info_hash_t info_hash;
  lt::piece_index_t piece;
  std::shared_ptr<std::promise<piece_entry>> promise;
  std::shared_future<piece_entry> future;

  piece_request(lt::info_hash_t info, lt::piece_index_t p,
                std::shared_ptr<std::promise<piece_entry>> pr)
      : info_hash(info), piece(p), promise(std::move(pr)),
        future(promise ? std::shared_future<piece_entry>(promise->get_future())
                       : std::shared_future<piece_entry>()) {}

  inline bool operator==(piece_request const &rq) const {
    return rq.info_hash == info_hash && rq.piece == piece;
  }

  inline bool operator<(piece_request const &rq) const {
    return info_hash == rq.info_hash ? piece < rq.piece
                                     : info_hash < rq.info_hash;
  }
};

namespace handler {
class alert_handler {

public:
  std::shared_ptr<lt::session> session;
  boost::filesystem::path save_path;

  alert_handler(lt::session_params params, boost::filesystem::path save_path);

  std::shared_future<piece_entry> schedule_piece(lt::torrent_handle &t,
                                                 lt::piece_index_t const piece);

  void wait_metadata(lt::torrent_handle &t);

  void join();

  void stop();

private:
  std::thread alert_thread_;

  typedef std::set<piece_request> requests_t;
  std::mutex requests_mtx_;
  requests_t requests_;

  std::mutex torrent_mtx_;
  std::condition_variable torrent_cv_;

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