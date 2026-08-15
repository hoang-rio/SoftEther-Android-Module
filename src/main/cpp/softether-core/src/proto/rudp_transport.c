#include "rudp_transport.h"
#include "softether_crypto.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <android/log.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define TAG "SoftEtherRUDPT"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Session states
#define RT_STATUS_CONNECT_SENT   0
#define RT_STATUS_ESTABLISHED    1
#define RT_STATUS_DISCONNECTED   2

// Monotonic time in milliseconds
static uint64_t rt_tick64(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

// Big-endian write/read helpers (match WRITE_UINT64/WRITE_UINT in MayaType.h)
static void rt_w64(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);  p[7] = (uint8_t)v;
}
static uint64_t rt_r64(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}
static void rt_w32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static uint32_t rt_r32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | ((uint32_t)p[3]);
}

// Simple ring-buffer FIFO
typedef struct {
    uint8_t* buf;
    uint32_t cap;
    uint32_t head;
    uint32_t size;
} rt_fifo_t;

static void rt_fifo_init(rt_fifo_t* f, uint32_t cap) {
    f->buf = (uint8_t*)malloc(cap);
    f->cap = f->buf != NULL ? cap : 0;
    f->head = 0;
    f->size = 0;
}
static void rt_fifo_free(rt_fifo_t* f) {
    free(f->buf);
    memset(f, 0, sizeof(*f));
}
static uint32_t rt_fifo_avail(const rt_fifo_t* f) {
    return f->cap - f->size;
}
static int rt_fifo_write(rt_fifo_t* f, const void* data, uint32_t len) {
    if (len > rt_fifo_avail(f)) {
        return -1;
    }
    uint32_t off = (f->head + f->size) % f->cap;
    uint32_t n1 = f->cap - off;
    if (n1 > len) n1 = len;
    memcpy(f->buf + off, data, n1);
    if (len > n1) {
        memcpy(f->buf, (const uint8_t*)data + n1, len - n1);
    }
    f->size += len;
    return 0;
}
static uint32_t rt_fifo_peek(const rt_fifo_t* f, void* data, uint32_t len) {
    if (len > f->size) len = f->size;
    uint32_t n1 = f->cap - f->head;
    if (n1 > len) n1 = len;
    memcpy(data, f->buf + f->head, n1);
    if (len > n1) {
        memcpy((uint8_t*)data + n1, f->buf, len - n1);
    }
    return len;
}
static void rt_fifo_advance(rt_fifo_t* f, uint32_t len) {
    if (len > f->size) len = f->size;
    f->head = (f->head + len) % f->cap;
    f->size -= len;
}

// One in-flight / received segment
typedef struct {
    uint64_t seq;
    uint32_t size;
    uint8_t data[RUDP_T_MAX_SEGMENT_SIZE];
    uint64_t next_send_tick;
    uint32_t num_sent;
} rt_segment_t;

typedef struct {
    int status;
    // Keys
    uint8_t key_init[RUDP_T_SHA1_SIZE];
    uint8_t key_send[RUDP_T_SHA1_SIZE];
    uint8_t key_recv[RUDP_T_SHA1_SIZE];
    uint8_t magic_req[RUDP_T_SHA1_SIZE];
    uint8_t magic_resp[RUDP_T_SHA1_SIZE];
    uint64_t magic_disconnect;
    uint8_t next_iv[RUDP_T_SHA1_SIZE];
    // Sequence tracking
    uint64_t next_send_seq;
    uint64_t last_recv_complete_seq;
    uint64_t your_tick;
    uint64_t latest_recv_my_tick;
    uint32_t current_rtt;
    uint64_t last_sent_tick;
    uint64_t next_keepalive_interval;
    uint64_t created_tick;
    // Peer endpoint
    uint32_t your_ip;   // network byte order
    uint16_t your_port; // host byte order
    // Send queue (sorted by seq)
    rt_segment_t send_segments[RUDP_T_MAX_NUM_ACK];
    uint32_t send_count;
    // Receive reorder buffer
    rt_segment_t recv_segments[RUDP_T_MAX_NUM_ACK];
    uint32_t recv_count;
    // Pending ACKs to send
    uint64_t reply_acks[RUDP_T_MAX_NUM_ACK];
    uint32_t reply_ack_count;
    // Byte FIFOs
    rt_fifo_t send_fifo;
    rt_fifo_t recv_fifo;
} rt_session_t;

struct rudp_transport {
    int udp_fd;
    int app_fd;
    int worker_fd;
    int error_code;
    int halt;
    pthread_t thread;
    int thread_started;
    uint32_t connect_timeout_ms;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int result_ready;
    int result_ok;
    rt_session_t se;
};

static void rt_send_udp(rudp_transport_t* t, const uint8_t* data, uint32_t size) {
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(t->se.your_port);
    dst.sin_addr.s_addr = t->se.your_ip;
    ssize_t n = sendto(t->udp_fd, data, size, 0,
                       (struct sockaddr*)&dst, sizeof(dst));
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        LOGD("rt: sendto failed: %s", strerror(errno));
    }
}

// Send one segment immediately (mirrors RUDPSendSegmentNow).
static void rt_send_segment_now(rudp_transport_t* t, uint64_t seq,
                                const void* data, uint32_t size) {
    rt_session_t* se = &t->se;
    uint8_t pkt[RUDP_T_MAX_PACKET_SIZE];
    uint8_t* p;
    uint8_t keygen[RUDP_T_SHA1_SIZE * 2];
    uint8_t key[RUDP_T_SHA1_SIZE];
    uint8_t sign[RUDP_T_SHA1_SIZE];
    uint8_t padlen;
    uint32_t current_size, next_iv_pos, num_ack, i;

    memset(pkt, 0, sizeof(pkt));

    // SIGN slot (filled with Key_Send for the sign calculation)
    memcpy(pkt, se->key_send, RUDP_T_SHA1_SIZE);
    p = pkt + RUDP_T_SHA1_SIZE;

    // IV
    memcpy(p, se->next_iv, RUDP_T_SHA1_SIZE);
    p += RUDP_T_SHA1_SIZE;

    // MyTick / YourTick / MAX_ACK
    rt_w64(p, rt_tick64()); p += 8;
    rt_w64(p, se->your_tick); p += 8;
    rt_w64(p, se->last_recv_complete_seq); p += 8;

    // NUM_ACK + ACKs
    num_ack = se->reply_ack_count;
    if (num_ack > RUDP_T_MAX_NUM_ACK) num_ack = RUDP_T_MAX_NUM_ACK;
    rt_w32(p, num_ack); p += 4;
    for (i = 0; i < num_ack; i++) {
        rt_w64(p, se->reply_acks[i]);
        p += 8;
    }
    se->reply_ack_count = 0;

    // SEQ
    rt_w64(p, seq); p += 8;

    // Payload
    if (size > 0 && data != NULL) {
        memcpy(p, data, size);
        p += size;
    }

    // Padding (1..255 bytes, value = padlen)
    padlen = (uint8_t)(rand() % 255) + 1;
    for (i = 0; i < padlen; i++) {
        *p = padlen;
        p++;
    }
    current_size = (uint32_t)(p - pkt);

    // Encrypt everything after the IV using RC4 with key = SHA1(iv || Key_Send)
    memcpy(keygen, se->next_iv, RUDP_T_SHA1_SIZE);
    memcpy(keygen + RUDP_T_SHA1_SIZE, se->key_send, RUDP_T_SHA1_SIZE);
        sha1_hash(keygen, sizeof(keygen), key);
    rc4_crypt(key, RUDP_T_SHA1_SIZE, pkt + RUDP_T_SHA1_SIZE * 2,
              current_size - RUDP_T_SHA1_SIZE * 2);

    // Sign over the whole packet, then overwrite the SIGN slot
    sha1_hash(pkt, current_size, sign);
    memcpy(pkt, sign, RUDP_T_SHA1_SIZE);

    rt_send_udp(t, pkt, current_size);

    if (size >= 1) {
        se->last_sent_tick = rt_tick64();
    }

    // Next IV: random 20 bytes copied from the packet just sent
    next_iv_pos = (uint32_t)(rand() % (current_size - RUDP_T_SHA1_SIZE));
    memcpy(se->next_iv, pkt + next_iv_pos, RUDP_T_SHA1_SIZE);
}

// Queue a new segment (mirrors RUDPSendSegment). Assigns the next send seq.
static void rt_queue_segment(rudp_transport_t* t, const void* data, uint32_t size) {
    rt_session_t* se = &t->se;
    if (se->send_count >= RUDP_T_MAX_NUM_ACK) {
        return;
    }
    rt_segment_t* s = &se->send_segments[se->send_count];
    memset(s, 0, sizeof(*s));
    if (size > 0 && data != NULL) {
        memcpy(s->data, data, size);
    }
    s->size = size;
    s->seq = se->next_send_seq++;
    se->send_count++;
}

// Remove a segment acknowledged by an exact sequence number
static void rt_process_ack(rudp_transport_t* t, uint64_t seq) {
    rt_session_t* se = &t->se;
    for (uint32_t i = 0; i < se->send_count; i++) {
        if (se->send_segments[i].seq == seq) {
            memmove(&se->send_segments[i], &se->send_segments[i + 1],
                    (se->send_count - i - 1) * sizeof(rt_segment_t));
            se->send_count--;
            return;
        }
    }
}

// Remove all segments with seq <= max_seq (cumulative ACK)
static void rt_process_ack2(rudp_transport_t* t, uint64_t max_seq) {
    rt_session_t* se = &t->se;
    uint32_t i = 0;
    while (i < se->send_count) {
        if (se->send_segments[i].seq <= max_seq) {
            memmove(&se->send_segments[i], &se->send_segments[i + 1],
                    (se->send_count - i - 1) * sizeof(rt_segment_t));
            se->send_count--;
        } else {
            i++;
        }
    }
}

static void rt_add_ack(rudp_transport_t* t, uint64_t seq) {
    rt_session_t* se = &t->se;
    for (uint32_t i = 0; i < se->reply_ack_count; i++) {
        if (se->reply_acks[i] == seq) return;
    }
    if (se->reply_ack_count < RUDP_T_MAX_NUM_ACK) {
        se->reply_acks[se->reply_ack_count++] = seq;
    }
}

// Handle an in-order payload (mirrors RUDPProcessRecvPayload)
static void rt_process_recv_payload(rudp_transport_t* t, uint64_t seq,
                                    const void* payload, uint32_t size) {
    rt_session_t* se = &t->se;
    if (seq > se->last_recv_complete_seq + RUDP_T_MAX_NUM_ACK) {
        // Beyond the window: ignore, do not ACK
        return;
    }
    if (seq <= se->last_recv_complete_seq) {
        rt_add_ack(t, seq);
        return;
    }
    for (uint32_t i = 0; i < se->recv_count; i++) {
        if (se->recv_segments[i].seq == seq) {
            rt_add_ack(t, seq);
            return;
        }
    }
    if (se->recv_count >= RUDP_T_MAX_NUM_ACK) {
        return;
    }
    rt_segment_t* s = &se->recv_segments[se->recv_count++];
    memset(s, 0, sizeof(*s));
    s->seq = seq;
    s->size = size;
    memcpy(s->data, payload, size);
    rt_add_ack(t, seq);
}

static void rt_signal_result(rudp_transport_t* t, int ok);

// Mark the session disconnected. Called from the worker thread only.
// by_you == 0: we initiate the tear-down, so send the 5 graceful disconnect
// segments first (mirrors RUDPDisconnectSession). by_you == 1: the peer
// already sent its disconnect magic; do not echo it.
static void rt_set_disconnected(rudp_transport_t* t, int by_you) {
    rt_session_t* se = &t->se;
    if (se->status == RT_STATUS_DISCONNECTED) {
        return;
    }
    if (by_you == 0 && se->status == RT_STATUS_ESTABLISHED) {
        uint32_t i;
        for (i = 0; i < 5; i++) {
            rt_send_segment_now(t, se->magic_disconnect, NULL, 0);
        }
    }
    se->status = RT_STATUS_DISCONNECTED;
    if (t->worker_fd >= 0) {
        shutdown(t->worker_fd, SHUT_RDWR);
    }
    rt_signal_result(t, 0);
}

static void rt_signal_result(rudp_transport_t* t, int ok) {
    pthread_mutex_lock(&t->lock);
    if (!t->result_ready) {
        t->result_ready = 1;
        t->result_ok = ok;
        pthread_cond_signal(&t->cond);
    }
    pthread_mutex_unlock(&t->lock);
}

// Verify sign and decrypt an incoming UDP packet; process it. Mirrors
// RUDPProcessRecvPacket + the client-side session dispatch.
static void rt_handle_udp_packet(rudp_transport_t* t, uint32_t src_ip,
                                 uint16_t src_port, const uint8_t* buf,
                                 uint32_t size) {
    rt_session_t* se = &t->se;
    uint8_t pkt[RUDP_T_MAX_PACKET_SIZE];
    uint8_t sign[RUDP_T_SHA1_SIZE];
    uint8_t keygen[RUDP_T_SHA1_SIZE * 2];
    uint8_t key[RUDP_T_SHA1_SIZE];
    uint8_t* p;
    uint8_t padlen;
    uint32_t enc_len, num_ack, i, payload_size;
    uint64_t my_tick, your_tick, max_ack, seq_no;

    if (se->status == RT_STATUS_DISCONNECTED) {
        return;
    }
    if (size < RUDP_T_SHA1_SIZE) {
        return;
    }

    // Packets shorter than 20 bytes: some NATs overwrite the server source
    // port; learn it while we are still awaiting the first valid segment.
    if (size < 20) {
        LOGD("rt: small pkt %u bytes from %u", size, src_port);
        if (se->status == RT_STATUS_CONNECT_SENT && src_ip == se->your_ip) {
            se->your_port = src_port;
        }
        return;
    }

    if (size > sizeof(pkt)) {
        size = sizeof(pkt);
    }
    memcpy(pkt, buf, size);

    // Verify the signature: SHA1 over the whole packet with the SIGN slot
    // replaced by Key_Recv.
    memcpy(sign, pkt, RUDP_T_SHA1_SIZE);
    memcpy(pkt, se->key_recv, RUDP_T_SHA1_SIZE);
    {
        uint8_t sign2[RUDP_T_SHA1_SIZE];
        sha1_hash(pkt, size, sign2);
        memcpy(pkt, sign, RUDP_T_SHA1_SIZE);
        if (memcmp(sign, sign2, RUDP_T_SHA1_SIZE) != 0) {
            LOGD("rt: sign verify FAILED on %u-byte pkt (state=%d)",
                 size, se->status);
            return;
        }
    }

    if (size < RUDP_T_SHA1_SIZE * 2) {
        return;
    }
    {
        const uint8_t* iv = pkt + RUDP_T_SHA1_SIZE;
        uint8_t* enc = pkt + RUDP_T_SHA1_SIZE * 2;
        enc_len = size - RUDP_T_SHA1_SIZE * 2;

        // Decrypt with RC4, key = SHA1(iv || Key_Recv)
        memcpy(keygen, iv, RUDP_T_SHA1_SIZE);
        memcpy(keygen + RUDP_T_SHA1_SIZE, se->key_recv, RUDP_T_SHA1_SIZE);
    sha1_hash(keygen, sizeof(keygen), key);
        rc4_crypt(key, RUDP_T_SHA1_SIZE, enc, enc_len);

        // Padding
        if (enc_len < 1) return;
        padlen = enc[enc_len - 1];
        if (padlen == 0) return;
        if (enc_len < padlen) return;
        enc_len -= padlen;

        // Header: MyTick YourTick MAX_ACK NUM_ACK [ACKs] SEQ
        if (enc_len < 8 + 8 + 8 + 4 + 8) return;
        p = enc;
        my_tick = rt_r64(p); p += 8;
        your_tick = rt_r64(p); p += 8;
        max_ack = rt_r64(p); p += 8;
        num_ack = rt_r32(p); p += 4;
        if (num_ack > RUDP_T_MAX_NUM_ACK) return;
        if (enc_len < 8 + 8 + 8 + 4 + num_ack * 8 + 8) return;
        if (your_tick > rt_tick64()) return;

        if (max_ack >= 1) rt_process_ack2(t, max_ack);
        for (i = 0; i < num_ack; i++) {
            uint64_t ack_seq = rt_r64(p);
            p += 8;
            rt_process_ack(t, ack_seq);
        }

        // Tick / RTT processing
        if (my_tick >= 2) my_tick--;
        if (my_tick > se->your_tick) se->your_tick = my_tick;
        if (your_tick > se->latest_recv_my_tick) {
            se->latest_recv_my_tick = your_tick;
        }

        seq_no = rt_r64(p);
        p += 8;

        if (seq_no == 0) return;
        if (seq_no == se->magic_disconnect) {
            // Peer requested a disconnect
            rt_set_disconnected(t, 1);
            return;
        }

        payload_size = enc_len - (uint32_t)(p - enc);
        if (payload_size > RUDP_T_MAX_SEGMENT_SIZE) {
            payload_size = 0;
        }
        if (payload_size >= 1) {
            rt_process_recv_payload(t, seq_no, p, payload_size);
        }

        if (se->status == RT_STATUS_CONNECT_SENT) {
            // First valid segment: session established
            LOGD("rt: valid segment from %u -> ESTABLISHED", src_port);
            se->status = RT_STATUS_ESTABLISHED;
            rt_signal_result(t, 1);
        }

        se->your_port = src_port;
    }
}

// Flush the receive FIFO into the socket pair (app-facing) end
static void rt_pump_recv_to_pair(rudp_transport_t* t) {
    rt_session_t* se = &t->se;
    uint8_t tmp[RUDP_T_MAX_SEGMENT_SIZE];
    while (se->recv_fifo.size >= 1) {
        uint32_t n = se->recv_fifo.size;
        if (n > sizeof(tmp)) n = sizeof(tmp);
        rt_fifo_peek(&se->recv_fifo, tmp, n);
        ssize_t w = send(t->worker_fd, tmp, n, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            rt_set_disconnected(t, 0);
            return;
        }
        if (w == 0) break;
        rt_fifo_advance(&se->recv_fifo, (uint32_t)w);
    }
}

// Read app data from the socket pair into the send FIFO
static void rt_pump_pair_to_send(rudp_transport_t* t) {
    rt_session_t* se = &t->se;
    uint8_t tmp[RUDP_T_MAX_SEGMENT_SIZE];
    for (;;) {
        if (se->send_fifo.size >= RUDP_T_MAX_FIFO_SIZE) break;
        ssize_t n = recv(t->worker_fd, tmp, sizeof(tmp), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            rt_set_disconnected(t, 0);
            return;
        }
        if (n == 0) {
            // App closed the connection
            rt_set_disconnected(t, 0);
            return;
        }
        rt_fifo_write(&se->send_fifo, tmp, (uint32_t)n);
    }
}

// Segment data from the send FIFO respecting the send window
static void rt_segment_send_fifo(rudp_transport_t* t) {
    rt_session_t* se = &t->se;
    uint8_t tmp[RUDP_T_MAX_SEGMENT_SIZE];
    for (;;) {
        uint64_t seq_min = se->send_count > 0 ? se->send_segments[0].seq : 0;
        if (seq_min != 0 &&
            (seq_min + RUDP_T_MAX_NUM_ACK - 1) < se->next_send_seq) {
            // Send window is full
            break;
        }
        uint32_t size = se->send_fifo.size;
        if (size == 0) break;
        if (size > RUDP_T_MAX_SEGMENT_SIZE) size = RUDP_T_MAX_SEGMENT_SIZE;
        rt_fifo_peek(&se->send_fifo, tmp, size);
        rt_queue_segment(t, tmp, size);
        rt_fifo_advance(&se->send_fifo, size);
    }
}

// Periodic session processing (mirrors RUDPInterruptProc client paths)
static void rt_interrupt(rudp_transport_t* t, uint64_t now) {
    rt_session_t* se = &t->se;

    if (se->status == RT_STATUS_CONNECT_SENT) {
        // Re-send the 39-byte connection request every 200ms
        if (se->last_sent_tick == 0 ||
            (now - se->last_sent_tick) >= RUDP_T_RESEND_TIMER) {
            uint8_t tmp[39];
            memcpy(tmp, se->key_init, RUDP_T_SHA1_SIZE);
            generate_random_bytes(tmp + RUDP_T_SHA1_SIZE, 19);
            rt_send_udp(t, tmp, 39);
            se->last_sent_tick = now;
        }
        if (now - se->created_tick >= t->connect_timeout_ms) {
            t->error_code = RUDP_T_ERR_TIMEOUT;
            rt_set_disconnected(t, 0);
        }
        return;
    }

    if (se->status != RT_STATUS_ESTABLISHED) {
        return;
    }

    // Fully silent for RUDP_TIMEOUT -> dead
    if (now >= se->latest_recv_my_tick + RUDP_T_TIMEOUT_MS) {
        t->error_code = RUDP_T_ERR_TIMEOUT;
        rt_set_disconnected(t, 0);
        return;
    }

    // Drain in-order received segments into the receive FIFO
    {
        uint64_t cur = se->last_recv_complete_seq;
        uint32_t i = 0;
        uint32_t drained = 0;
        while (i < se->recv_count) {
            cur++;
            rt_segment_t* s = &se->recv_segments[i];
            if (s->seq != cur) break;
            if (s->size == RUDP_T_SHA1_SIZE &&
                memcmp(s->data, se->magic_req, RUDP_T_SHA1_SIZE) == 0) {
                // KeepAlive Request received; respond if the queue is empty
                if (se->send_count == 0) {
                    rt_queue_segment(t, se->magic_resp, RUDP_T_SHA1_SIZE);
                }
            } else if (s->size == RUDP_T_SHA1_SIZE &&
                       memcmp(s->data, se->magic_resp, RUDP_T_SHA1_SIZE) == 0) {
                // KeepAlive Response received; nothing to do
            } else {
                if (rt_fifo_write(&se->recv_fifo, s->data, s->size) != 0) {
                    // Receive FIFO full: stop draining until it is flushed
                    break;
                }
            }
            se->last_recv_complete_seq = s->seq;
            drained = i + 1;
            i++;
        }
        if (drained > 0) {
            memmove(&se->recv_segments[0], &se->recv_segments[drained],
                    (se->recv_count - drained) * sizeof(rt_segment_t));
            se->recv_count -= drained;
        }
    }

    // Deliver to the app, ingest app data
    rt_pump_recv_to_pair(t);
    rt_pump_pair_to_send(t);
    rt_segment_send_fifo(t);

    // Periodic keepalive
    if (se->last_sent_tick == 0 ||
        now >= se->last_sent_tick + se->next_keepalive_interval) {
        if (se->send_count == 0) {
            rt_queue_segment(t, se->magic_req, RUDP_T_SHA1_SIZE);
        }
        se->next_keepalive_interval = RUDP_T_KEEPALIVE_MIN +
            (uint32_t)(rand() % (RUDP_T_KEEPALIVE_MAX - RUDP_T_KEEPALIVE_MIN));
    }

    // Retransmit due segments with exponential backoff
    {
        uint64_t seq_min = se->send_count > 0 ? se->send_segments[0].seq : 0;
        for (uint32_t j = 0; j < se->send_count; j++) {
            rt_segment_t* s = &se->send_segments[j];
            if (s->seq > seq_min + RUDP_T_MAX_NUM_ACK - 1) continue;
            if (s->next_send_tick != 0 && now < s->next_send_tick) continue;
            uint32_t interval;
            uint32_t shift = s->num_sent < 10 ? s->num_sent : 10;
            if (se->current_rtt != 0) {
                interval = (se->current_rtt * 120 / 100) * ((uint32_t)1 << shift);
            } else {
                interval = RUDP_T_RESEND_TIMER * ((uint32_t)1 << shift);
            }
            if (interval > RUDP_T_RESEND_TIMER_MAX) {
                interval = RUDP_T_RESEND_TIMER_MAX;
            }
            s->num_sent++;
            s->next_send_tick = now + interval;
            rt_send_segment_now(t, s->seq, s->data, s->size);
        }
    }

    // Drain pending ACKs
    while (se->reply_ack_count >= 1) {
        rt_send_segment_now(t, se->next_send_seq, NULL, 0);
    }
}

static int rt_compute_poll_timeout(rudp_transport_t* t, uint64_t now) {
    rt_session_t* se = &t->se;
    uint64_t deadline = now + RUDP_T_LOOP_WAIT_MS;

    if (se->status == RT_STATUS_CONNECT_SENT) {
        uint64_t nx = se->last_sent_tick + RUDP_T_RESEND_TIMER;
        if (nx < deadline) deadline = nx;
        uint64_t cto = se->created_tick + t->connect_timeout_ms;
        if (cto < deadline) deadline = cto;
    } else if (se->status == RT_STATUS_ESTABLISHED) {
        uint64_t ka = se->last_sent_tick + se->next_keepalive_interval;
        if (ka < deadline) deadline = ka;
        for (uint32_t i = 0; i < se->send_count; i++) {
            if (se->send_segments[i].next_send_tick != 0 &&
                se->send_segments[i].next_send_tick < deadline) {
                deadline = se->send_segments[i].next_send_tick;
            }
        }
        uint64_t to = se->latest_recv_my_tick + RUDP_T_TIMEOUT_MS;
        if (to < deadline) deadline = to;
        if (se->reply_ack_count >= 1 || se->recv_fifo.size >= 1 ||
            se->send_fifo.size >= 1) {
            deadline = now;
        }
    }

    if (now >= deadline) return 0;
    uint64_t diff = deadline - now;
    if (diff > 1000) diff = 1000;
    return (int)diff;
}

static void* rt_worker(void* param) {
    rudp_transport_t* t = (rudp_transport_t*)param;
    rt_session_t* se = &t->se;
    uint8_t buf[RUDP_T_MAX_PACKET_SIZE];

    while (!t->halt) {
        uint64_t now = rt_tick64();

        // Drain the UDP socket
        for (;;) {
            struct sockaddr_in src;
            socklen_t slen = sizeof(src);
            memset(&src, 0, sizeof(src));
            ssize_t n = recvfrom(t->udp_fd, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&src, &slen);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (t->halt) break;
                break;
            }
            if (n == 0) break;
            rt_handle_udp_packet(t, src.sin_addr.s_addr, ntohs(src.sin_port),
                                 buf, (uint32_t)n);
        }

        if (se->status != RT_STATUS_DISCONNECTED) {
            rt_interrupt(t, rt_tick64());
        }

        if (t->halt) break;
        if (se->status == RT_STATUS_DISCONNECTED && t->result_ready) break;

        // Wait for the next event
        int timeout = rt_compute_poll_timeout(t, rt_tick64());
        struct pollfd fds[2];
        memset(fds, 0, sizeof(fds));
        fds[0].fd = t->udp_fd;
        fds[0].events = POLLIN;
        fds[1].fd = t->worker_fd;
        fds[1].events = POLLIN;
        if (se->recv_fifo.size >= 1) {
            fds[1].events |= POLLOUT;
        }
        poll(fds, 2, timeout);
    }

    // Graceful disconnect signals if the session is still up
    rt_set_disconnected(t, 0);

    return NULL;
}

rudp_transport_t* rudp_transport_create(void) {
    rudp_transport_t* t = (rudp_transport_t*)calloc(1, sizeof(*t));
    if (t == NULL) return NULL;
    t->udp_fd = -1;
    t->app_fd = -1;
    t->worker_fd = -1;
    t->error_code = RUDP_T_ERR_UNKNOWN;
    pthread_mutex_init(&t->lock, NULL);
    // rt_tick64() uses CLOCK_MONOTONIC, so the cond var must too; otherwise
    // pthread_cond_timedwait treats the deadline as a realtime timestamp and
    // returns ETIMEDOUT immediately on Linux (glibc). macOS does not expose
    // pthread_condattr_setclock (its cond timers are monotonic by default).
#if defined(__linux__)
    pthread_condattr_t cattr;
    pthread_condattr_init(&cattr);
    pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
    pthread_cond_init(&t->cond, &cattr);
    pthread_condattr_destroy(&cattr);
#else
    pthread_cond_init(&t->cond, NULL);
#endif
    srand((unsigned int)(rt_tick64() ^ (uint64_t)(uintptr_t)t));
    return t;
}

// Derive session keys from the init key (mirrors RUDPNewSession). The string
// is appended with a big-endian (len+1) prefix and no NUL (WriteBufStr).
static void rt_derive_key(const uint8_t* init_key, uint8_t* out, const char* s) {
    size_t slen = strlen(s);
    uint8_t buf[RUDP_T_SHA1_SIZE + 4 + 64];
    memcpy(buf, init_key, RUDP_T_SHA1_SIZE);
    rt_w32(buf + RUDP_T_SHA1_SIZE, (uint32_t)(slen + 1));
    memcpy(buf + RUDP_T_SHA1_SIZE + 4, s, slen);
    sha1_hash(buf, RUDP_T_SHA1_SIZE + 4 + (uint32_t)slen, out);
}

static void rt_derive_keys(rt_session_t* se) {
    uint8_t key1[RUDP_T_SHA1_SIZE];
    uint8_t key2[RUDP_T_SHA1_SIZE];
    uint8_t buf[RUDP_T_SHA1_SIZE * 2 + 4 + 64];
    size_t slen;

    // key1 = SHA1(init_key || BE32(8) || "zurukko")
    rt_derive_key(se->key_init, key1, "zurukko");

    // key2 = SHA1(init_key || key1 || BE32(12) || "yasushineko")
    slen = strlen("yasushineko");
    memcpy(buf, se->key_init, RUDP_T_SHA1_SIZE);
    memcpy(buf + RUDP_T_SHA1_SIZE, key1, RUDP_T_SHA1_SIZE);
    rt_w32(buf + RUDP_T_SHA1_SIZE * 2, (uint32_t)(slen + 1));
    memcpy(buf + RUDP_T_SHA1_SIZE * 2 + 4, "yasushineko", slen);
    sha1_hash(buf, RUDP_T_SHA1_SIZE * 2 + 4 + (uint32_t)slen, key2);

    // Client: Key_Send = key2, Key_Recv = key1
    memcpy(se->key_send, key2, RUDP_T_SHA1_SIZE);
    memcpy(se->key_recv, key1, RUDP_T_SHA1_SIZE);

    // Keepalive magic values
    rt_derive_key(se->key_init, se->magic_req, "Magic_KeepAliveRequest");
    rt_derive_key(se->key_init, se->magic_resp, "Magic_KeepAliveResponse");

    // Client-side disconnect magic
    {
        uint8_t rnd[4];
        uint64_t low;
        if (generate_random_bytes(rnd, sizeof(rnd)) == 0) {
            low = ((uint64_t)rnd[0] << 24) | ((uint64_t)rnd[1] << 16) |
                  ((uint64_t)rnd[2] << 8) | (uint64_t)rnd[3];
        } else {
            low = (uint64_t)rand();
        }
        se->magic_disconnect = 0xffffffff00000000ULL | low;
    }
}

static int rt_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int rudp_transport_connect(rudp_transport_t* t, const rudp_transport_config_t* cfg) {
    rt_session_t* se;
    int fds[2] = {-1, -1};
    int udp_fd = -1;
    int result = -1;
    uint32_t timeout_ms;
    uint64_t deadline;
    struct timespec ts;

    if (t == NULL || cfg == NULL || cfg->server_ip == 0 ||
        cfg->server_port == 0) {
        t->error_code = RUDP_T_ERR_UNKNOWN;
        return -1;
    }

    timeout_ms = cfg->connect_timeout_ms != 0 ? cfg->connect_timeout_ms
                                              : RUDP_T_TIMEOUT_MS;
    t->connect_timeout_ms = timeout_ms;

    // UDP socket
    if (cfg->udp_fd >= 0) {
        udp_fd = cfg->udp_fd;
    } else {
        udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_fd < 0) {
            t->error_code = RUDP_T_ERR_UNKNOWN;
            return -1;
        }
        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port = 0;
        if (bind(udp_fd, (struct sockaddr*)&local, sizeof(local)) != 0) {
            close(udp_fd);
            t->error_code = RUDP_T_ERR_UNKNOWN;
            return -1;
        }
    }
    if (rt_set_nonblocking(udp_fd) != 0) {
        if (cfg->udp_fd < 0) close(udp_fd);
        t->error_code = RUDP_T_ERR_UNKNOWN;
        return -1;
    }
    t->udp_fd = udp_fd;

    // Socket pair: [0] = worker end, [1] = app-facing end
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        t->error_code = RUDP_T_ERR_UNKNOWN;
        goto fail;
    }
    if (rt_set_nonblocking(fds[0]) != 0) {
        goto fail;
    }
    t->worker_fd = fds[0];
    t->app_fd = fds[1];

    // Initialize the session
    se = &t->se;
    memset(se, 0, sizeof(*se));
    se->status = RT_STATUS_CONNECT_SENT;
    se->your_ip = cfg->server_ip;
    se->your_port = cfg->server_port;
    se->created_tick = rt_tick64();
    if (generate_random_bytes(se->key_init, RUDP_T_SHA1_SIZE) != 0) {
        t->error_code = RUDP_T_ERR_UNKNOWN;
        goto fail;
    }
    rt_derive_keys(se);
    generate_random_bytes(se->next_iv, RUDP_T_SHA1_SIZE);
    se->next_send_seq = 1;
    se->latest_recv_my_tick = rt_tick64();
    se->next_keepalive_interval = RUDP_T_KEEPALIVE_MIN +
        (uint32_t)(rand() % (RUDP_T_KEEPALIVE_MAX - RUDP_T_KEEPALIVE_MIN));
    rt_fifo_init(&se->send_fifo, RUDP_T_MAX_FIFO_SIZE);
    rt_fifo_init(&se->recv_fifo, RUDP_T_MAX_FIFO_SIZE);
    if (se->send_fifo.cap == 0 || se->recv_fifo.cap == 0) {
        t->error_code = RUDP_T_ERR_UNKNOWN;
        goto fail;
    }

    // The very first payload is the big-endian Magic_Disconnect value
    {
        uint8_t md[8];
        rt_w64(md, se->magic_disconnect);
        rt_fifo_write(&se->send_fifo, md, sizeof(md));
    }

    // Start the worker
    t->halt = 0;
    if (pthread_create(&t->thread, NULL, rt_worker, t) != 0) {
        t->error_code = RUDP_T_ERR_UNKNOWN;
        goto fail;
    }
    t->thread_started = 1;

    // Wait for the result (established or failed)
    deadline = rt_tick64() + timeout_ms + 1000;
    pthread_mutex_lock(&t->lock);
    while (!t->result_ready) {
        ts.tv_sec = (time_t)(deadline / 1000);
        ts.tv_nsec = (long)(deadline % 1000) * 1000000L;
        if (pthread_cond_timedwait(&t->cond, &t->lock, &ts) != 0) {
            break;
        }
    }
    result = t->result_ready && t->result_ok ? 0 : -1;
    pthread_mutex_unlock(&t->lock);

    if (result == 0) {
        t->error_code = RUDP_T_ERR_OK;
        return 0;
    }

    if (t->error_code == RUDP_T_ERR_OK) {
        t->error_code = RUDP_T_ERR_TIMEOUT;
    }

fail:
    if (t->thread_started) {
        t->halt = 1;
        if (t->worker_fd >= 0) shutdown(t->worker_fd, SHUT_RDWR);
        pthread_join(t->thread, NULL);
        t->thread_started = 0;
    }
    if (t->udp_fd >= 0) { close(t->udp_fd); t->udp_fd = -1; }
    if (t->worker_fd >= 0) { close(t->worker_fd); t->worker_fd = -1; }
    if (t->app_fd >= 0) { close(t->app_fd); t->app_fd = -1; }
    rt_fifo_free(&t->se.send_fifo);
    rt_fifo_free(&t->se.recv_fifo);
    return -1;
}

int rudp_transport_get_fd(rudp_transport_t* t) {
    if (t == NULL) return -1;
    return t->app_fd;
}

int rudp_transport_get_udp_fd(rudp_transport_t* t) {
    if (t == NULL) return -1;
    return t->udp_fd;
}

int rudp_transport_get_error(rudp_transport_t* t) {
    if (t == NULL) return RUDP_T_ERR_UNKNOWN;
    return t->error_code;
}

void rudp_transport_disconnect(rudp_transport_t* t) {
    if (t == NULL) return;
    t->halt = 1;
    if (t->worker_fd >= 0) {
        shutdown(t->worker_fd, SHUT_RDWR);
    }
}

void rudp_transport_destroy(rudp_transport_t* t) {
    if (t == NULL) return;
    t->halt = 1;
    if (t->thread_started) {
        if (t->worker_fd >= 0) shutdown(t->worker_fd, SHUT_RDWR);
        pthread_join(t->thread, NULL);
        t->thread_started = 0;
    }
    if (t->worker_fd >= 0) { close(t->worker_fd); t->worker_fd = -1; }
    if (t->app_fd >= 0) { close(t->app_fd); t->app_fd = -1; }
    if (t->udp_fd >= 0) { close(t->udp_fd); t->udp_fd = -1; }
    rt_fifo_free(&t->se.send_fifo);
    rt_fifo_free(&t->se.recv_fifo);
    pthread_mutex_destroy(&t->lock);
    pthread_cond_destroy(&t->cond);
    free(t);
}
