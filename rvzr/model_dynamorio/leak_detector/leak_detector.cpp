/// Fast leak detector for Revizor DR traces.
///
/// Usage: leak_detector <reference_trace> <target_trace> <output_file>
///
/// Reads two binary trace files produced by the DynamoRIO tracer, compares
/// them entry-by-entry, and writes all I-Leaks and D-Leaks to a binary output
/// file.  Output is truncated to include only leaks up to and including the
/// last architectural I-Leak.

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <optional>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "leak.h"
#include "trace_reader.h"

// ===================================================================
// Local Helpers
// ===================================================================

/// @brief This class is responsible of serializing leak reports to a file.
class LeakPrinter
{
  public:
    /// @param fname Path of the output file
    /// @param ref_reader Buffered reader of the reference trace
    /// @param tgt_reader Buffered reader of the target trace
    LeakPrinter(const char *fname, const TraceReader &ref_reader, const TraceReader &tgt_reader)
        : out(fopen(fname, "wb")), ref_reader(ref_reader), tgt_reader(tgt_reader)
    {
        if (out == nullptr) {
            fprintf(stderr, "Cannot create output file %s", fname);
            exit(1);
        }
    }

    ~LeakPrinter() { fclose(out); }

    LeakPrinter(const LeakPrinter &) = delete;
    LeakPrinter &operator=(const LeakPrinter &) = delete;
    LeakPrinter(LeakPrinter &&) = delete;
    LeakPrinter &operator=(LeakPrinter &&) = delete;

    /// @brief Serialize a D-Leak (memory access divergence) to disk
    /// @param ref_inst Instruction in the reference trace that caused the divergence
    /// @param tgt_inst Instruction in the target trace that caused the divergence
    void report_d_leak(const TracedInst &ref_inst, const TracedInst &tgt_inst)
    {
        const leak_t leak = {.pc = ref_inst.pc,
                             .type = leak_type_t::D_LEAK,
                             .spec_level = ref_inst.spec_level,
                             .ref_idx = ref_inst.trace_idx,
                             .tgt_idx = tgt_inst.trace_idx};
        fwrite(&leak, sizeof(leak_t), 1, out);
    }

    /// @brief Serialize a I-Leak (PC divergence) to disk
    /// @param ref_inst Instruction in the reference trace that caused the divergence
    /// @param tgt_inst Instruction in the target trace that caused the divergence
    void report_i_leak(const TracedInst &ref_inst, const TracedInst &tgt_inst)
    {
        // For I-leaks, we blame the instruction immediately preceding the divergence,
        // i.e. the last executed branch.
        const auto [ref_pc, ref_spec_level, ref_idx] = ref_reader.get_prev(ref_inst.trace_idx);
        const auto [tgt_pc, tgt_spec_level, tgt_idx] = tgt_reader.get_prev(tgt_inst.trace_idx);
        assert(ref_pc == tgt_pc);
        assert(ref_spec_level == tgt_spec_level);

        const leak_t leak = {.pc = ref_pc,
                             .type = leak_type_t::I_LEAK,
                             .spec_level = ref_spec_level,
                             .ref_idx = ref_idx,
                             .tgt_idx = tgt_idx};
        fwrite(&leak, sizeof(leak_t), 1, out);
    }

  private:
    FILE *out;
    const TraceReader &ref_reader;
    const TraceReader &tgt_reader;
};

/// @brief Check if @param ref and @param tgt access the same memory
static bool have_same_accesses(const TracedInst &ref, const TracedInst &tgt)
{
    // Check that the number of reads and writes match
    if (ref.reads.size() != tgt.reads.size() or ref.writes.size() != tgt.writes.size())
        return false;
    // Check read addresses
    for (size_t i = 0; i < ref.reads.size(); i++)
        if (ref.reads[i].address != tgt.reads[i].address)
            return false;
    // Check write addresses
    for (size_t i = 0; i < ref.writes.size(); i++)
        if (ref.writes[i].address != tgt.writes[i].address)
            return false;
    // No difference found
    return true;
}

// ===================================================================
// Main
// ===================================================================

int main(int argc, char *argv[])

{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <reference_trace> <target_trace> <output_file>\n", argv[0]);
        return 1;
    }

    TraceReader ref_reader(argv[1]);
    TraceReader tgt_reader(argv[2]);
    LeakPrinter printer(argv[3], ref_reader, tgt_reader);

    // Read first entry of both traces
    auto ref_inst = ref_reader.next();
    auto tgt_inst = tgt_reader.next();

    // Check that both traces start from same spec level and pc
    assert(ref_inst.has_value());
    assert(tgt_inst.has_value());
    assert(ref_inst->spec_level == tgt_inst->spec_level);
    assert(ref_inst->pc == tgt_inst->pc);

    // Follow both traces at the same time
    while (ref_inst.has_value() and tgt_inst.has_value()) {
        // Uneven spec windows - skip the rest of the speculative window until they are back at the
        // same level
        if (ref_inst->spec_level > tgt_inst->spec_level) {
            ref_inst = ref_reader.skip_spec_window(ref_inst->spec_level);
            if (not ref_inst.has_value())
                break; // trace ended

        } else if (tgt_inst->spec_level > ref_inst->spec_level) {
            tgt_inst = tgt_reader.skip_spec_window(tgt_inst->spec_level);
            if (not tgt_inst.has_value())
                break; // trace ended
        }

        // Now we are at the same level.
        assert(ref_inst->spec_level == tgt_inst->spec_level);

        if (ref_inst->pc != tgt_inst->pc) {
            printer.report_i_leak(*ref_inst, *tgt_inst);
            // If it's an architectural PC divergence, don't analyse further
            if (ref_inst->spec_level == 0)
                break;
            // If it's speculative, skip this rest of the speculation window
            ref_inst = ref_reader.skip_spec_window(ref_inst->spec_level);
            tgt_inst = tgt_reader.skip_spec_window(tgt_inst->spec_level);
            continue;
        }

        if (not have_same_accesses(*ref_inst, *tgt_inst)) {
            printer.report_d_leak(*ref_inst, *tgt_inst);
        }

        ref_inst = ref_reader.next();
        tgt_inst = tgt_reader.next();
    }

    return 0;
}
