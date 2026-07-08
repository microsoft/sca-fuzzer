///
/// File: harness.c
///       A complete, single-file MCFuzz reference harness.
///
///       It adapts the fuzzer's raw input to the API of the stand-in "external"
///       library in libdummy/, which contains a deliberately non-constant-time
///       primitive. Everything the harness itself needs -- argument parsing,
///       policy and input parsing, a deterministic stack, and output saving --
///       lives in this one file.
///
///       Usage: reference-harness -d <input> -p <policy> [-o <output>]
///

#include "harness.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dummy_lib.h"

// =================================================================================================
// Diagnostics
// =================================================================================================
#define WARN(msg, ...)        fprintf(stderr, "[WARN] " msg "\n", ##__VA_ARGS__)
#define INPUT_ERR(msg, ...)   fprintf(stderr, "[INPUT_ERR] " msg "\n", ##__VA_ARGS__)
#define HARNESS_ERR(msg, ...) fprintf(stderr, "[HARNESS_ERR] " msg "\n", ##__VA_ARGS__)

// =================================================================================================
// Field sizes and input constraints
// =================================================================================================
#define KEY_SIZE           (16)
#define IV_SIZE            (16)
#define MAX_PLAINTEXT_SIZE (4096)

#define MIN_PRIV_RATIO     (0x01)
#define MIN_PRIV_SIZE      (16)
#define MIN_PUB_SIZE       (16)
#define MIN_DATA_SIZE      (sizeof(harness_config_t) + MIN_PRIV_SIZE + MIN_PUB_SIZE)
#define PRIV_RATIO_DIVISOR (256)

#define N_POLICY_FIELDS          (3)
#define POLICY_LINE_MAX_LEN      (256)
#define DETERMINISTIC_STACK_SIZE (64 * 4096ULL) // 256 KiB

// =================================================================================================
// Output
// =================================================================================================
static const char *g_output_path = NULL;

/// @brief Write @p len bytes of public output to `g_output_path`. No-op when the
///        path is NULL. Best-effort: failures warn but do not abort.
static void save_public_output(const uint8_t *data, size_t len)
{
    if (g_output_path == NULL)
        return;

    FILE *f = fopen(g_output_path, "wb");
    if (!f) {
        WARN("Could not open output file '%s' for writing", g_output_path);
        return;
    }
    size_t written = fwrite(data, 1, len, f);
    if (written != len)
        WARN("Incomplete write to '%s': %zu of %zu bytes", g_output_path, written, len);
    fclose(f);
}

// =================================================================================================
// Input field extraction
// =================================================================================================
/// @brief A read-only view into a region of the input data.
typedef struct {
    const uint8_t *ptr;
    size_t len;
} fat_ptr_t;

/// @brief Cursor state for reading fields out of the public/private regions.
typedef struct {
    const input_t *pub;
    size_t pub_cursor;
    const input_t *priv;
    size_t priv_cursor;
} parser_state_t;

/// @brief Return a pointer to @p size bytes from the public or private region,
///        advancing the corresponding cursor. NULL if the region is exhausted.
static const uint8_t *extract_pointer(bool is_public, size_t size, parser_state_t *p)
{
    size_t cursor = is_public ? p->pub_cursor : p->priv_cursor;
    size_t max_cursor = is_public ? p->pub->size : p->priv->size;
    if (cursor + size > max_cursor) {
        INPUT_ERR("Not enough %s data to extract %zu bytes", is_public ? "public" : "private",
                  size);
        return NULL;
    }

    const uint8_t *ptr;
    if (is_public) {
        ptr = p->pub->data + cursor;
        p->pub_cursor += size;
    } else {
        ptr = p->priv->data + cursor;
        p->priv_cursor += size;
    }
    return ptr;
}

/// @brief Take a fixed-size field of @p size bytes.
static int set_field(bool is_public, size_t size, parser_state_t *p, fat_ptr_t *out)
{
    out->ptr = extract_pointer(is_public, size, p);
    if (out->ptr == NULL)
        return -1;
    out->len = size;
    return 0;
}

/// @brief Take the rest of the plaintext's region, capped at @p max_size.
static int set_plaintext(bool is_public, size_t max_size, parser_state_t *p, fat_ptr_t *out)
{
    size_t remaining =
        is_public ? (p->pub->size - p->pub_cursor) : (p->priv->size - p->priv_cursor);
    size_t size = remaining < max_size ? remaining : max_size;
    if (size == 0)
        return -1;
    return set_field(is_public, size, p, out);
}

// =================================================================================================
// Input blob and policy parsing
// =================================================================================================
/// @brief Split the raw input blob into its config header and the private and
///        public data regions.
static int parse_data_blob(const input_t *data, harness_config_t *config, input_t *priv,
                           input_t *pub)
{
    if (data->size < MIN_DATA_SIZE) {
        INPUT_ERR("Input size %zu is smaller than the minimum %zu", data->size,
                  (size_t)MIN_DATA_SIZE);
        return -1;
    }

    // The fixed-size configuration header prefixes the blob.
    memcpy(config, data->data, sizeof(*config));
    if (config->priv_ratio < MIN_PRIV_RATIO) {
        INPUT_ERR("Invalid priv_ratio %u", config->priv_ratio);
        return -1;
    }

    // Split the remaining bytes into private and public regions exactly as
    // MCFuzz's boosting stage computes the split.
    size_t total = data->size - sizeof(*config);
    size_t priv_size = ((size_t)config->priv_ratio * total) / PRIV_RATIO_DIVISOR;
    size_t pub_size = total - priv_size;
    if (priv_size < MIN_PRIV_SIZE) {
        INPUT_ERR("Private data size %zu is smaller than the minimum %d", priv_size, MIN_PRIV_SIZE);
        return -1;
    }
    if (pub_size < MIN_PUB_SIZE) {
        INPUT_ERR("Public data size %zu is smaller than the minimum %d", pub_size, MIN_PUB_SIZE);
        return -1;
    }

    priv->data = data->data + sizeof(*config);
    priv->size = priv_size;
    pub->data = priv->data + priv_size;
    pub->size = pub_size;
    return 0;
}

/// @brief Parse the three-line policy file into @p policy.
static int parse_policy(const char *fname, policy_t *policy)
{
    FILE *file = fopen(fname, "r");
    if (!file) {
        HARNESS_ERR("Cannot open policy file %s: %s", fname, strerror(errno));
        return -1;
    }

    bool key_set = false;
    bool iv_set = false;
    bool plaintext_set = false;

    char line[POLICY_LINE_MAX_LEN];
    for (int i = 0; i < N_POLICY_FIELDS; i++) {
        if (!fgets(line, sizeof(line), file)) {
            INPUT_ERR("Failed to read line %d from policy file %s", i + 1, fname);
            fclose(file);
            return -1;
        }
        line[strcspn(line, "\n")] = '\0';

        if (strcmp(line, "key: public") == 0) {
            policy->key_is_public = true;
            key_set = true;
        } else if (strcmp(line, "key: private") == 0) {
            policy->key_is_public = false;
            key_set = true;
        } else if (strcmp(line, "iv: public") == 0) {
            policy->iv_is_public = true;
            iv_set = true;
        } else if (strcmp(line, "iv: private") == 0) {
            policy->iv_is_public = false;
            iv_set = true;
        } else if (strcmp(line, "plaintext: public") == 0) {
            policy->plaintext_is_public = true;
            plaintext_set = true;
        } else if (strcmp(line, "plaintext: private") == 0) {
            policy->plaintext_is_public = false;
            plaintext_set = true;
        } else {
            INPUT_ERR("Invalid line in policy file %s: %s", fname, line);
            fclose(file);
            return -1;
        }
    }

    if (fgets(line, sizeof(line), file)) {
        INPUT_ERR("Extra line in policy file %s", fname);
        fclose(file);
        return -1;
    }
    if (!key_set || !iv_set || !plaintext_set) {
        INPUT_ERR("Not all fields are set in policy file %s", fname);
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

// =================================================================================================
// Cipher: adapt fuzzer input to the library API
// =================================================================================================
static int run_cipher(const input_t *priv, const input_t *pub, const policy_t *policy)
{
    parser_state_t parser = {.pub = pub, .pub_cursor = 0, .priv = priv, .priv_cursor = 0};

    fat_ptr_t key = {0};
    fat_ptr_t iv = {0};
    fat_ptr_t plaintext = {0};
    if (set_field(policy->key_is_public, KEY_SIZE, &parser, &key) != 0) {
        HARNESS_ERR("Failed to read key");
        return -1;
    }
    if (set_field(policy->iv_is_public, IV_SIZE, &parser, &iv) != 0) {
        HARNESS_ERR("Failed to read IV");
        return -1;
    }
    if (set_plaintext(policy->plaintext_is_public, MAX_PLAINTEXT_SIZE, &parser, &plaintext) != 0) {
        HARNESS_ERR("Failed to read plaintext");
        return -1;
    }

    uint8_t *ciphertext = (uint8_t *)malloc(plaintext.len);
    if (!ciphertext) {
        HARNESS_ERR("Failed to allocate %zu bytes for ciphertext", plaintext.len);
        return -1;
    }

    dummy_cipher_encrypt(key.ptr, key.len, iv.ptr, iv.len, plaintext.ptr, ciphertext,
                         plaintext.len);
    save_public_output(ciphertext, plaintext.len);
    free(ciphertext);
    return 0;
}

// =================================================================================================
// Tracing entry point
// =================================================================================================
int start_harness(policy_t *policy, input_t *data)
{
    harness_config_t config = {0};
    input_t priv = {0};
    input_t pub = {0};
    if (parse_data_blob(data, &config, &priv, &pub) != 0)
        return -1;

    // One-time library setup (analogous to SymCryptInit). Input-independent, so
    // it produces no leak of its own.
    dummy_lib_init();

    return run_cipher(&priv, &pub, policy);
}

// =================================================================================================
// Deterministic execution
// =================================================================================================
/// @brief Allocate a fixed-size stack at a deterministic address.
static void *get_deterministic_stack(void)
{
    void *stack = mmap(NULL, DETERMINISTIC_STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
        HARNESS_ERR("mmap failed for deterministic stack");
        return NULL;
    }
    return stack;
}

/// @brief Switch to @p new_stack, call `start_harness`, then restore the stack.
static int deterministic_start_harness(policy_t *policy, input_t *data, const void *new_stack)
{
    int result = 0;
    uint64_t new_rsp = (uint64_t)new_stack + DETERMINISTIC_STACK_SIZE;

    // Switch to the fixed stack, call start_harness(policy, data), then restore
    // the original stack. policy is passed in %rdi and data in %rsi per the
    // System V AMD64 calling convention.
    asm volatile(""
                 "pushq %%rbp\n"
                 "movq %%rsp, %%rbp\n"
                 "movq %1, %%rsp\n"
                 "pushq %%rbp\n"
                 "movq %%rsp, %%rbp\n"

                 "sub $8, %%rsp\n" // keep the stack 16-byte aligned at the call
                 "callq %P4\n"
                 "add $8, %%rsp\n"

                 "popq %%rbp\n"
                 "movq %%rbp, %%rsp\n"
                 "popq %%rbp\n"

                 : "=a"(result)
                 : "r"(new_rsp), "D"(policy), "S"(data), "p"(start_harness)
                 : "memory");
    return result;
}

// =================================================================================================
// Command-line interface
// =================================================================================================
static void print_usage(const char *program)
{
    fprintf(stderr, "Usage: %s -d <input> -p <policy> [-o <output>]\n", program);
    fprintf(stderr, "  -d file   Input blob generated by the fuzzer (config + private + public).\n");
    fprintf(stderr, "  -p file   Data-classification policy file.\n");
    fprintf(stderr, "  -o file   Optional file to receive the public output (ciphertext).\n");
    fprintf(stderr, "  -h        Show this help message.\n");
}

static int read_args(int argc, char *argv[], char **data_file, char **policy_file)
{
    int opt;
    while ((opt = getopt(argc, argv, "d:p:o:h")) != -1) {
        switch (opt) {
        case 'd':
            *data_file = optarg;
            break;
        case 'p':
            *policy_file = optarg;
            break;
        case 'o':
            g_output_path = optarg;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!*data_file || !*policy_file) {
        print_usage(argv[0]);
        return 1;
    }
    return 0;
}

static int load_data_file(const char *fname, input_t *data)
{
    FILE *file = fopen(fname, "rb");
    if (!file) {
        HARNESS_ERR("Cannot open file %s: %s", fname, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fileno(file), &st) != 0) {
        HARNESS_ERR("Cannot stat file %s: %s", fname, strerror(errno));
        fclose(file);
        return -1;
    }
    if (st.st_size <= 0) {
        INPUT_ERR("File %s is empty", fname);
        fclose(file);
        return -1;
    }

    uint8_t *buffer = (uint8_t *)malloc((size_t)st.st_size);
    if (!buffer) {
        HARNESS_ERR("Cannot allocate %ld bytes for file %s", (long)st.st_size, fname);
        fclose(file);
        return -1;
    }

    size_t n = fread(buffer, 1, (size_t)st.st_size, file);
    fclose(file);
    if (n != (size_t)st.st_size) {
        HARNESS_ERR("Only read %zu of %ld bytes from %s", n, (long)st.st_size, fname);
        free(buffer);
        return -1;
    }

    data->data = buffer;
    data->size = (size_t)st.st_size;
    return 0;
}

int main(int argc, char *argv[])
{
    // The first allocation must be the deterministic stack, so that its address
    // does not depend on the input or the environment.
    void *new_stack = get_deterministic_stack();
    if (new_stack == NULL) {
        HARNESS_ERR("Failed to allocate deterministic stack");
        return 1;
    }

    char *data_fname = NULL;
    char *policy_fname = NULL;
    if (read_args(argc, argv, &data_fname, &policy_fname) != 0)
        return 1;

    policy_t policy = {0};
    if (parse_policy(policy_fname, &policy) != 0) {
        INPUT_ERR("Failed to parse policy file %s", policy_fname);
        return 1;
    }

    input_t data = {0};
    if (load_data_file(data_fname, &data) != 0)
        return 1;

    int rc = deterministic_start_harness(&policy, &data, new_stack);

    free((void *)data.data);
    return rc == 0 ? 0 : 1;
}
