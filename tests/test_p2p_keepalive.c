/*
 * test_p2p_keepalive.c — keepalive decision for a peer record.
 *
 * Background (mainnet 2026-11): the keepalive thread pinged only links idle for
 * MXD_KEEPALIVE_INTERVAL, but connection liveness was refreshed only by PING/PONG.
 * A busy link (height polls every 5 s) never saw a PING, so the reaper tore it
 * down every MXD_KEEPALIVE_TIMEOUT on both ends — permanent reconnect churn,
 * head-block re-broadcasts on every handshake, and "Failed to connect" errors.
 * Received messages also went to a record keyed by the inbound socket's
 * ephemeral port, so the record the reaper watched (listen port) starved.
 *
 * mxd_p2p_peer_liveness is the pure decision used by the keepalive thread:
 * silence is measured from the last message received, or from activation when
 * nothing was ever received; a PING is due only when nothing was sent for the
 * interval.
 */

#include "../include/mxd_p2p.h"
#include "test_utils.h"

#include <stdio.h>
#include <time.h>

#define INTERVAL 15
#define TIMEOUT  45

static mxd_peer_liveness_t decide(time_t now, time_t activated_at, time_t last_sent, time_t last_received) {
    return mxd_p2p_peer_liveness(now, activated_at, last_sent, last_received, INTERVAL, TIMEOUT);
}

static void test_busy_link_is_healthy(void) {
    TEST_START("busy link: recent traffic both ways needs no ping and never times out");
    const time_t t0 = 1000000;
    TEST_ASSERT(decide(t0 + 100, t0, t0 + 98, t0 + 97) == MXD_PEER_LIVENESS_OK, "sent 2 s ago, received 3 s ago -> OK");
    TEST_ASSERT(decide(t0 + 100, t0, t0 + 99, t0 + 60) == MXD_PEER_LIVENESS_OK, "received 40 s ago (< timeout), sent 1 s ago -> OK");
    /* A link that is busy for hours but whose peer keeps answering never times out. */
    time_t now = t0;
    int ok = 1;
    for (int i = 0; i < 3600; i++) {
        now += 5;
        if (decide(now, t0, now - 1, now - 2) != MXD_PEER_LIVENESS_OK) ok = 0;
    }
    TEST_ASSERT(ok, "hours of 5 s polls with replies: always OK");
    TEST_END("busy link");
}

static void test_idle_link_pings_then_times_out(void) {
    TEST_START("idle link: ping after the interval, time out after the timeout of silence");
    const time_t t0 = 2000000;
    TEST_ASSERT(decide(t0 + 10, t0, t0, t0) == MXD_PEER_LIVENESS_OK, "10 s idle -> OK");
    TEST_ASSERT(decide(t0 + INTERVAL - 1, t0, t0, t0) == MXD_PEER_LIVENESS_OK, "just before the interval -> OK");
    TEST_ASSERT(decide(t0 + INTERVAL, t0, t0, t0) == MXD_PEER_LIVENESS_PING, "at the interval -> PING");
    TEST_ASSERT(decide(t0 + 30, t0, t0 + 15, t0) == MXD_PEER_LIVENESS_PING, "pinged 15 s ago, still silent -> PING again");
    TEST_ASSERT(decide(t0 + TIMEOUT, t0, t0 + 30, t0) == MXD_PEER_LIVENESS_PING, "exactly the timeout of silence -> not yet timed out");
    TEST_ASSERT(decide(t0 + TIMEOUT + 1, t0, t0 + 30, t0) == MXD_PEER_LIVENESS_TIMED_OUT, "beyond the timeout of silence -> TIMED_OUT");
    /* A reply resets the silence window (a send 15 s ago would still ask for a ping). */
    TEST_ASSERT(decide(t0 + 60, t0, t0 + 50, t0 + 50) == MXD_PEER_LIVENESS_OK, "PONG at +50, sent at +50 -> OK again");
    TEST_ASSERT(decide(t0 + 60, t0, t0 + 45, t0 + 50) == MXD_PEER_LIVENESS_PING, "PONG at +50 but nothing sent for 15 s -> PING");
    TEST_END("idle link");
}

static void test_half_open_link_is_detected(void) {
    TEST_START("half-open link: sends succeed but nothing ever comes back");
    const time_t t0 = 3000000;
    /* Never heard from the peer: silence is measured from activation. */
    TEST_ASSERT(decide(t0 + 10, t0, t0 + 9, 0) == MXD_PEER_LIVENESS_OK, "never received, activated 10 s ago, sent 1 s ago -> OK");
    TEST_ASSERT(decide(t0 + 20, t0, 0, 0) == MXD_PEER_LIVENESS_PING, "never sent -> PING");
    TEST_ASSERT(decide(t0 + TIMEOUT + 1, t0, t0 + TIMEOUT, 0) == MXD_PEER_LIVENESS_TIMED_OUT,
                "sent every few seconds for 46 s with no reply -> TIMED_OUT (the old code never noticed)");
    /* Heard from it once long ago, we keep sending: still timed out. */
    TEST_ASSERT(decide(t0 + 200, t0, t0 + 199, t0 + 100) == MXD_PEER_LIVENESS_TIMED_OUT, "received 100 s ago, sent 1 s ago -> TIMED_OUT");
    TEST_END("half-open link");
}

static void test_unknown_history(void) {
    TEST_START("no history at all: ask for a ping, never time out on nothing");
    TEST_ASSERT(decide(4000000, 0, 0, 0) == MXD_PEER_LIVENESS_PING, "no timestamps -> PING");
    TEST_ASSERT(decide(4000000, 0, 3999999, 0) == MXD_PEER_LIVENESS_OK, "sent 1 s ago, no activation time, never received -> OK");
    /* Clock going backwards must not produce a timeout. */
    TEST_ASSERT(decide(4000000, 4000100, 4000100, 4000100) == MXD_PEER_LIVENESS_PING, "timestamps in the future -> PING, not TIMED_OUT");
    TEST_END("no history");
}

int main(void) {
    printf("=== P2P keepalive decision tests ===\n");
    test_busy_link_is_healthy();
    test_idle_link_pings_then_times_out();
    test_half_open_link_is_detected();
    test_unknown_history();
    printf("\nAll P2P keepalive tests passed.\n");
    return 0;
}
