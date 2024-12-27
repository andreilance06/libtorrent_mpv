#ifndef ALERT_HANDLER
#define ALERT_HANDLER

#include <libtorrent/alert_types.hpp>
#include <libtorrent/hex.hpp>
#include <libtorrent/session.hpp>
#include <atomic>
#include <condition_variable>
#include <future>
#include <mutex>

struct piece_entry
{
    boost::shared_array<char> buffer;
    int size{-1};
    lt::piece_index_t piece{-1};
};

struct piece_request
{
    lt::info_hash_t info_hash;
    lt::piece_index_t piece{-1};
    std::shared_ptr<std::promise<piece_entry>> promise;

    inline bool operator==(piece_request const &rq) const
    {
        return rq.info_hash == info_hash && rq.piece == piece;
    }

    inline bool operator<(piece_request const &rq) const
    {
        return info_hash == rq.info_hash ? piece < rq.piece : info_hash < rq.info_hash;
    }
};

namespace handler
{
    class alert_handler
    {
    private:
        std::mutex mtx_;
        std::thread alert_thread_;
        std::atomic_bool stop_{};

        typedef std::multiset<piece_request> requests_t;
        requests_t requests_;
        std::map<lt::info_hash_t, std::set<lt::piece_index_t>> have_pieces_;

        std::mutex metadata_mtx_;
        std::condition_variable metadata_cv_;

        void handle_alert(lt::alert *a);

        void handle_read_piece_alert(lt::read_piece_alert *a);

        void handle_piece_finished_alert(lt::piece_finished_alert *a);

        void handle_add_torrent_alert(lt::add_torrent_alert *a);

        void handle_metadata_received_alert(lt::metadata_received_alert *a);

        void handle_torrent_interrupt(lt::info_hash_t info_hash);

    public:

        lt::session &session;

        alert_handler(lt::session &ses);

        ~alert_handler();

        std::shared_future<piece_entry> schedule_piece(lt::torrent_handle &t, lt::piece_index_t const piece);

        void wait_metadata(lt::torrent_handle &t);
    };
}

#endif