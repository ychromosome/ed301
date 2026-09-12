#define _POSIX_C_SOURCE 200809L

/* Core-only adaptation of the bound v1 dudect harness. No EVP/provider shim. */
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DUDECT_IMPLEMENTATION
#include "third_party/dudect/dudect.h"

#define BATCH_MEASUREMENTS 2000U
#define SEED_BYTES 38U

typedef struct timing_slot_st TIMING_SLOT;
extern TIMING_SLOT *ed301_timing_new(const unsigned char *seed, uint8_t prepared);
extern void ed301_timing_free(TIMING_SLOT *slot);
extern uint8_t ed301_timing_sign(const TIMING_SLOT *slot);
extern uint8_t ed301_timing_expand(const TIMING_SLOT *slot);

enum { POSITIVE_CONTROL, PREPARED_SIGN, SEED_EXPANSION, TEST_COUNT };
static const char *const labels[] = { "positive-control", "prepared-sign", "seed-expansion" };
static TIMING_SLOT *slots[BATCH_MEASUREMENTS];
static unsigned char seeds[BATCH_MEASUREMENTS][SEED_BYTES];
static int current_test;
static size_t preparation_failures, operation_failures;
static volatile uint64_t sink;

void prepare_inputs(dudect_config_t *configuration, uint8_t *input_data, uint8_t *classes)
{
    size_t i, j;

    for (i = 0; i < configuration->number_measurements; i++) {
        uint32_t index = (uint32_t)i;

        ed301_timing_free(slots[i]);
        slots[i] = NULL;
        classes[i] = randombit();
        memcpy(input_data + i * configuration->chunk_size, &index, sizeof(index));
        if (classes[i] == 0) {
            for (j = 0; j < SEED_BYTES; j++)
                seeds[i][j] = (unsigned char)j;
        } else {
            randombytes(seeds[i], SEED_BYTES);
        }
        if (current_test != POSITIVE_CONTROL) {
            slots[i] = ed301_timing_new(seeds[i], current_test == PREPARED_SIGN);
            if (slots[i] == NULL)
                preparation_failures++;
        }
    }
}

uint8_t do_one_computation(uint8_t *data)
{
    uint32_t index;
    uint8_t ok;

    memcpy(&index, data, sizeof(index));
    if (current_test == POSITIVE_CONTROL) {
        uint64_t accumulator = 0;
        size_t bit;

        for (bit = 0; bit < 8 * SEED_BYTES; bit++) {
            if (((seeds[index][bit / 8] >> (bit % 8)) & 1U) != 0) {
                accumulator += (accumulator ^ bit) * UINT64_C(0x9e3779b97f4a7c15);
                accumulator = (accumulator << 13) | (accumulator >> 51);
            }
        }
        sink = accumulator;
        return 1;
    }
    ok = current_test == PREPARED_SIGN
        ? ed301_timing_sign(slots[index]) : ed301_timing_expand(slots[index]);
    if (!ok)
        operation_failures++;
    return ok;
}

int main(int argc, char **argv)
{
    size_t measurements = 200000, batches, i, j;
    int detected[TEST_COUNT] = { 0 }, test;
    double peaks[TEST_COUNT] = { 0 };

    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        unsigned char seed[SEED_BYTES] = { 0 };
        TIMING_SLOT *slot = ed301_timing_new(seed, 1);
        int ok = slot != NULL && ed301_timing_sign(slot) == 1
            && ed301_timing_expand(slot) == 1;

        ed301_timing_free(slot);
        puts(ok ? "core_timing_adapter=PASS" : "core_timing_adapter=FAIL");
        return ok ? 0 : 2;
    }
    if (argc == 2) {
        char *end;
        unsigned long long parsed;

        errno = 0;
        parsed = strtoull(argv[1], &end, 10);
        if (errno != 0 || argv[1][0] < '0' || argv[1][0] > '9'
                || *end != '\0' || parsed < 200000 || parsed > 10000000)
            return 2;
        measurements = (size_t)parsed;
    } else if (argc != 1) {
        return 2;
    }
    batches = (measurements + BATCH_MEASUREMENTS - 1) / BATCH_MEASUREMENTS + 1;
    printf("core_timing_tool=dudect requested_per_test=%zu batches=%zu threshold_abs_t=%d\n",
        measurements, batches, t_threshold_moderate);
    for (test = 0; test < TEST_COUNT; test++) {
        dudect_config_t configuration = { sizeof(uint32_t), BATCH_MEASUREMENTS };
        dudect_ctx_t context;
        double final_t;

        current_test = test;
        preparation_failures = operation_failures = 0;
        if (dudect_init(&context, &configuration) != 0)
            return 2;
        for (i = 0; i < batches; i++) {
            dudect_state_t state = dudect_main(&context);

            detected[test] |= state == DUDECT_LEAKAGE_FOUND;
            for (j = 0; j < DUDECT_TESTS; j++) {
                ttest_ctx_t *bucket = context.ttest_ctxs[j];
                if (bucket->n[0] > DUDECT_ENOUGH_MEASUREMENTS
                        && bucket->n[1] > DUDECT_ENOUGH_MEASUREMENTS) {
                    double t = fabs(t_compute(bucket));
                    if (!isfinite(t))
                        return 2;
                    if (t > peaks[test])
                        peaks[test] = t;
                }
            }
        }
        final_t = fabs(t_compute(max_test(&context)));
        printf("CORE_TIMING test=%s peak_abs_t=%.6f final_abs_t=%.6f raw_n0=%.0f raw_n1=%.0f prepare_errors=%zu operation_errors=%zu detected=%d\n",
            labels[test], peaks[test], final_t, context.ttest_ctxs[0]->n[0],
            context.ttest_ctxs[0]->n[1], preparation_failures, operation_failures, detected[test]);
        if (!isfinite(final_t) || context.ttest_ctxs[0]->n[0] <= DUDECT_ENOUGH_MEASUREMENTS
                || context.ttest_ctxs[0]->n[1] <= DUDECT_ENOUGH_MEASUREMENTS
                || preparation_failures != 0 || operation_failures != 0)
            return 2;
        dudect_free(&context);
        for (i = 0; i < BATCH_MEASUREMENTS; i++) {
            ed301_timing_free(slots[i]);
            slots[i] = NULL;
        }
    }
    if (!detected[POSITIVE_CONTROL]) {
        puts("core_timing=INCONCLUSIVE positive_control_not_detected");
        return 3;
    }
    if (detected[PREPARED_SIGN] || detected[SEED_EXPANSION]) {
        puts("core_timing=LEAK");
        return 1;
    }
    puts("core_timing=PASS scope=core_fixed_vs_random_seed_not_a_constant_time_proof");
    return 0;
}
