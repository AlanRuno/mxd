#ifndef MXD_RSC_INTERNAL_H
#define MXD_RSC_INTERNAL_H

// Performance thresholds
#define MXD_MAX_RESPONSE_TIME 5000    // Maximum acceptable response time (ms)
#define MXD_MIN_RESPONSE_COUNT 10      // Minimum responses needed for ranking
#define MXD_INACTIVE_THRESHOLD 300000  // Node considered inactive after 5 minutes
#define MXD_RELIABILITY_WEIGHT 0.3     // Weight for reliability in ranking
#define MXD_SPEED_WEIGHT 0.4          // Weight for speed in ranking
#define MXD_STAKE_WEIGHT 0.3          // Weight for stake in ranking

#endif // MXD_RSC_INTERNAL_H
