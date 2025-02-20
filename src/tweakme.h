/**
 * @file tweakme.h
 * @brief Tweak this file to modify eRPC's behavior
 */
#pragma once

#include <assert.h>
#include <stdlib.h>

namespace erpc {

/// Packet loss timeout for an RPC request in microseconds
static constexpr size_t kRpcRTOUs = 5000;

// For nano sleeps of encryption
static constexpr size_t kNanoSleep = false;
static constexpr size_t kSleepLength = 5;

// For batched encryption
static constexpr size_t kBatchEncryptSize = 8;
static constexpr size_t kBatchEncryptSim = false;

// Congestion control
static constexpr bool kEnableCc = true;  // TODO change
static constexpr bool kEnableCcOpts = true;

static constexpr bool kCcRTT = kEnableCc;       ///< Measure per-packet RTT
static constexpr bool kCcRateComp = kEnableCc;  ///< Perform rate computation
static constexpr bool kCcPacing = kEnableCc;    ///< Use rate limiter for pacing

/// Sample RDTSC once per RX/TX batch for RTT measurements
static constexpr bool kCcOptBatchTsc = kEnableCcOpts;

/// Bypass timing wheel if a session is uncongested
static constexpr bool kCcOptWheelBypass = kEnableCcOpts;

/// Bypass Timely rate update if session is uncongested and RTT is below T_low
static constexpr bool kCcOptTimelyBypass = kEnableCcOpts;

static_assert(kCcRTT || !kCcRateComp, "");  // Rate comp => RTT measurement

static constexpr bool kDatapathStats = false;
}  // namespace erpc
