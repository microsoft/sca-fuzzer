/// Marges all fast detector reports into a single JSON dict.
///
/// Usage: merger <stage4_folder>
///
/// Reads every .leaks file contained in stage4_folder and parses it to create
/// a global map of leaks. This map is printed as a JSON dict to stdout.

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "leak.h"

namespace fs = std::filesystem;

using spec_level_t = uint8_t;
using PerPCMap = std::map<uint64_t, std::vector<std::string>>;
using PerLeakTypeMap = std::map<leak_type_t, PerPCMap>;
using PerClauseMap = std::map<spec_level_t, PerLeakTypeMap>;

/// @brief Print a map of <PC, List[location]> in json format:
///
///      "0xdead" : [seed1/001:1234:1234, seed1/002:1234:1234, seed2/001:4567:4567],
///      "0xbeef" : [seed1/001:4567:4567, seed1/002:1234:1234],
///
void dump_json(const PerPCMap &map)
{
    bool first_pc = true;
    for (auto const &[pc, refs] : map) {
        if (!first_pc)
            std::cout << ",\n";
        first_pc = false;

        char buf[20];
        std::snprintf(buf, sizeof(buf), "0x%lx", pc);
        std::cout << "  \"" << buf << "\": [";

        for (std::size_t i = 0; i < refs.size(); ++i) {
            if (i)
                std::cout << ", ";
            std::cout << "\"" << refs[i] << "\"";
        }
        std::cout << "]";
    }
}

/// @brief Print a map of <LeakType, PCMap> in json format:
///
///    "D" : {
///        "0xdead" : [seed1/001:1234:1234, seed1/002:1234:1234, seed2/001:4567:4567]
///     },
///    "I" : {
///        "0xbeef" : [seed1/001:4567:4567, seed1/002:1234:1234]
///     }
///
void dump_json(const PerLeakTypeMap &map)
{
    bool first = true;
    for (auto const &[leak_type, pc_map] : map) {
        if (!first)
            std::cout << ",\n";
        first = false;

        if (leak_type == leak_type_t::D_LEAK)
            std::cout << "  \"D\": {\n";
        else if (leak_type == leak_type_t::I_LEAK)
            std::cout << "  \"I\": {\n";
        else
            std::cout << "  \"Unknown\": {\n";

        dump_json(pc_map);
        std::cout << "\n}";
    }
}

/// @brief Print a map of <ClauseName, LeakTypeMap> in json format:
///
/// "cond" : {
///    "D" : {
///        "0xdead" : [seed1/001:1234:1234, seed1/002:1234:1234, seed2/001:4567:4567]
///     },
///    "I" : {
///        "0xbeef" : [seed1/001:4567:4567, seed1/002:1234:1234]
///     }
///  },
/// "seq" : {
///    "D" : {
///        "0xdead" : [seed1/001:1234:1234, seed1/002:1234:1234, seed2/001:4567:4567]
///     },
///    "I" : {
///        "0xbeef" : [seed1/001:4567:4567, seed1/002:1234:1234]
///     }
///  }
///
void dump_json(const PerClauseMap &map)
{
    bool first = true;
    for (auto const &[spec_level, type_map] : map) {
        if (!first)
            std::cout << ",\n";
        first = false;

        if (spec_level > 0)
            std::cout << "  \"cond\": {\n";
        else
            std::cout << "  \"seq\": {\n";

        dump_json(type_map);
        std::cout << "\n}";
    }
}

int main(int argc, char *argv[])
{
    // Parse command-line arguments
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <stage4_folder>\n";
        return 1;
    }

    fs::path root(argv[1]);
    if (!fs::is_directory(root)) {
        std::cerr << "Not a directory: " << root << "\n";
        return 1;
    }

    // Build leak maps
    PerClauseMap leak_map;
    for (auto const &subdir_entry : fs::directory_iterator(root)) {
        if (!subdir_entry.is_directory())
            continue;
        // Iterate over the stage4 subdirectories to find .leaks files
        for (auto const &file_entry : fs::directory_iterator(subdir_entry.path())) {
            if (!file_entry.is_regular_file())
                continue;
            if (file_entry.path().extension() != ".leaks")
                continue;
            std::ifstream f(file_entry.path(), std::ios::binary);
            if (!f)
                continue;
            // Read a single .leaks file and add all leaks to the map
            leak_t leak;
            while (f.read(reinterpret_cast<char *>(&leak), sizeof(leak_t))) {
                std::string tag = file_entry.path().string() + ":" + std::to_string(leak.ref_idx) +
                                  ":" + std::to_string(leak.tgt_idx);
                leak_map[leak.spec_level][leak.type][leak.pc].push_back(std::move(tag));
            }
        }
    }

    // Emit JSON
    std::cout << "{\n";
    dump_json(leak_map);
    std::cout << "\n}\n";

    return 0;
}
