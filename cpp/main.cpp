// =============================================================================
// main.cpp — WHIR PCS 基准测试 CLI，命令行参数与 Rust 二进制保持一致。
//
// 流程概览：
//   1. 解析命令行参数 → Args
//   2. 构建 ProtocolParameters → 派生 Config（确定各轮 fold/sumcheck/PoW 参数）
//   3. 构造与 Rust 侧 bit-exact 一致的 DomainSeparator（通过 CBOR 规范化）
//   4. 生成测试多项式向量，执行 commit → prove → proof 导出
//   5. 循环 N 次 verify 并统计性能（证明耗时 / 证明大小 / 验证吞吐）
// =============================================================================

#include "whir/algebra/embedding.hpp"
#include "whir/algebra/goldilocks.hpp"
#include "whir/algebra/goldilocks_ext2.hpp"
#include "whir/algebra/goldilocks_ext3.hpp"
#include "whir/algebra/linear_form.hpp"
#include "whir/hash/blake3_engine.hpp"
#include "whir/hash/hash_counter.hpp"
#include "whir/hash/sha2_engine.hpp"
#include "whir/parameters.hpp"
#include "whir/protocols/whir/whir.hpp"
#include "whir/transcript/transcript.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using Clock = std::chrono::high_resolution_clock;

// 命令行参数结构体，所有默认值与 Rust src/bin/main.rs 对齐，
// 确保不传参数时两端可复现一致的 config / proof。
struct Args {
    std::string protocol_type = "PCS";
    std::size_t security_level = 128;
    std::size_t pow_bits = 20;
    std::size_t num_variables = 20;
    std::size_t num_evaluations = 1;
    std::size_t log_inv_rate = 1;
    std::size_t verifier_repetitions = 1000;
    std::size_t folding_factor = 4;
    std::string soundness_type = "ConjectureList";
    std::string fold_optimisation = "ProverHelps";
    std::string field = "Goldilocks3";
    std::string hash = "Blake3";
};

[[noreturn]] void fail(std::string_view message) {
    std::fprintf(stderr, "error: %.*s\n", static_cast<int>(message.size()), message.data());
    std::exit(1);
}

void print_help() {
    std::printf("Usage: whir_cli [OPTIONS]\n\n");
    std::printf("Options:\n");
    std::printf("  -t, --type <PROTOCOL_TYPE>             [default: PCS]\n");
    std::printf("  -l, --security-level <SECURITY_LEVEL>  [default: 128]\n");
    std::printf("  -p, --pow-bits <POW_BITS>              [default: 20]\n");
    std::printf("  -d, --num-variables <NUM_VARIABLES>    [default: 20]\n");
    std::printf("  -e, --evaluations <NUM_EVALUATIONS>    [default: 1]\n");
    std::printf("  -r, --rate <RATE>                      [default: 1]\n");
    std::printf("      --reps <VERIFIER_REPETITIONS>      [default: 1000]\n");
    std::printf("  -k, --fold <FOLDING_FACTOR>            [default: 4]\n");
    std::printf("      --sec <SOUNDNESS_TYPE>             [default: ConjectureList]\n");
    std::printf("      --fold_type <FOLD_OPTIMISATION>    [default: ProverHelps]\n");
    std::printf("  -f, --field <FIELD>                    [default: Goldilocks3]\n");
    std::printf("      --hash <MERKLE_TREE>               [default: Blake3]\n");
    std::printf("  -h, --help                             Print help\n");
    std::exit(0);
}

std::string take_value(int& i, int argc, char* argv[], std::string_view option) {
    if (i + 1 >= argc) {
        std::string msg = "missing value for ";
        msg += option;
        fail(msg);
    }
    return argv[++i];
}

//解析命令行参数
Args parse_args(int argc, char* argv[]) { //argc表示用户在命令行输入的参数个数, argv是一个包含字符串的数组，存储了用户的每一个具体参数
    Args args;
    for (int i = 1; i < argc; ++i) { //从i=1开始遍历,因为argv[0]是程序名
        std::string arg = argv[i]; //取出当前遍历到的参数,转换成更易操作的std::string
        if (arg == "-t" || arg == "--type") 
            //4. 如果用户输入了 "-t" 或者 "--type" (通常一个是简写，一个是全称)
            args.protocol_type = take_value(i, argc, argv, arg);
            // 5. 那么就调用 take_value 函数把紧跟着的值取出来，并赋给 args.protocol_type。
            // 注意：take_value 函数内部很可能会修改 'i' 的值，或者自己往后看一个位置，因为参数通常是成对出现的（标志 + 值）。
        else if (arg == "-l" || arg == "--security-level")
            args.security_level = std::stoull(take_value(i, argc, argv, arg));
        else if (arg == "-p" || arg == "--pow-bits")
            args.pow_bits = std::stoull(take_value(i, argc, argv, arg));
        else if (arg == "-d" || arg == "--num-variables")
            args.num_variables = std::stoull(take_value(i, argc, argv, arg));
        else if (arg == "-e" || arg == "--evaluations")
            args.num_evaluations = std::stoull(take_value(i, argc, argv, arg));
        else if (arg == "-r" || arg == "--rate")
            args.log_inv_rate = std::stoull(take_value(i, argc, argv, arg));
        else if (arg == "--reps")
            args.verifier_repetitions = std::stoull(take_value(i, argc, argv, arg));
        else if (arg == "-k" || arg == "--fold")
            args.folding_factor = std::stoull(take_value(i, argc, argv, arg));
        else if (arg == "--sec")
            args.soundness_type = take_value(i, argc, argv, arg);
        else if (arg == "--fold_type")
            args.fold_optimisation = take_value(i, argc, argv, arg);
        else if (arg == "-f" || arg == "--field")
            args.field = take_value(i, argc, argv, arg);
        else if (arg == "--hash")
            args.hash = take_value(i, argc, argv, arg);
        else if (arg == "-h" || arg == "--help")
            print_help();
        else {
            std::string msg = "unknown option ";
            msg += arg;
            fail(msg);
        }
    }
    return args;
}

// 将命令行 hash 名称映射为引擎 ID，仅支持 Blake3 / Sha2。
::whir::EngineId hash_id_from_name(const std::string& name) {
    if (name == "Blake3") return ::whir::hash::ENGINE_ID_BLAKE3;
    if (name == "Sha2") return ::whir::hash::ENGINE_ID_SHA2;
    fail("unsupported hash; expected Blake3 or Sha2");
}

// ─── 以下 CBOR 辅助函数用于将 ProtocolParameters 序列化为确定性字节串，
// 再经 SHA3-512 哈希生成与 Rust 侧 bit-exact 一致的 DomainSeparator。
// 必须手动编码而不能依赖通用 CBOR 库，以确保键序、整数编码方式与 Rust 严格一致。

void cbor_write_bool(std::vector<std::uint8_t>& out, bool value) {
    out.push_back(value ? 0xF5 : 0xF4);
}

void cbor_write_map_header(std::vector<std::uint8_t>& out, std::size_t len) {
    if (len <= 23) {
        out.push_back(static_cast<std::uint8_t>(0xA0 + len));
        return;
    }
    fail("CBOR map too large for this helper");
}

void cbor_write_engine_id(std::vector<std::uint8_t>& out, const ::whir::EngineId& id) {
    ::whir::transcript::cbor_array_header(out, id.bytes().size());
    for (auto byte : id.bytes()) {
        ::whir::transcript::cbor_write_uint(out, byte);
    }
}

void cbor_write_protocol_parameters(
    std::vector<std::uint8_t>& out,
    const ::whir::ProtocolParameters& params)
{
    cbor_write_map_header(out, 8);
    ::whir::transcript::cbor_write_text(out, "unique_decoding");
    cbor_write_bool(out, params.unique_decoding);
    ::whir::transcript::cbor_write_text(out, "starting_log_inv_rate");
    ::whir::transcript::cbor_write_uint(out, params.starting_log_inv_rate);
    ::whir::transcript::cbor_write_text(out, "initial_folding_factor");
    ::whir::transcript::cbor_write_uint(out, params.initial_folding_factor);
    ::whir::transcript::cbor_write_text(out, "folding_factor");
    ::whir::transcript::cbor_write_uint(out, params.folding_factor);
    ::whir::transcript::cbor_write_text(out, "security_level");
    ::whir::transcript::cbor_write_uint(out, params.security_level);
    ::whir::transcript::cbor_write_text(out, "pow_bits");
    ::whir::transcript::cbor_write_uint(out, params.pow_bits);
    ::whir::transcript::cbor_write_text(out, "batch_size");
    ::whir::transcript::cbor_write_uint(out, params.batch_size);
    ::whir::transcript::cbor_write_text(out, "hash_id");
    cbor_write_engine_id(out, params.hash_id);
}

// 构造与 Rust CLI 完全一致的 DomainSeparator：
//   protocol_id = SHA3-512(CBOR(params))
//   session_id  = SHA3-256(CBOR("Example at src/bin/main.rs:133"))
// 这是 C++ / Rust 生成可互验 proof 的前提。
::whir::transcript::DomainSeparator make_rust_cli_domain_separator(
    const ::whir::ProtocolParameters& params)
{
    ::whir::transcript::DomainSeparator ds;
    std::vector<std::uint8_t> cbor_params;
    cbor_write_protocol_parameters(cbor_params, params);
    sha3_512_hash(cbor_params.data(), cbor_params.size(), ds.protocol_id.data());

    std::vector<std::uint8_t> cbor_session;
    ::whir::transcript::cbor_write_text(cbor_session, "Example at src/bin/main.rs:133");
    sha3_256_hash(cbor_session.data(), cbor_session.size(), ds.session_id.data());
    return ds;
}

// 打印 WHIR 协议的派生参数：各轮 commit / sumcheck / PoW 配置及安全位数。
// 若任何子模块的实际 PoW 难度超出用户指定的 pow_bits，末尾输出警告。
template <typename M>
void print_config(
    const Args& args,
    const ::whir::ProtocolParameters& params,
    const ::whir::protocols::whir::Config<M>& config)
{
    using Target = typename M::Target;
    bool more_pow_bits_required =
        static_cast<double>(config.initial_skip_pow.difficulty()) > params.pow_bits
        || static_cast<double>(config.initial_sumcheck.round_pow.difficulty()) > params.pow_bits
        || static_cast<double>(config.final_pow.difficulty()) > params.pow_bits
        || static_cast<double>(config.final_sumcheck.round_pow.difficulty()) > params.pow_bits;
    for (const auto& rc : config.round_configs) {
        more_pow_bits_required =
            more_pow_bits_required
            || static_cast<double>(rc.pow.difficulty()) > params.pow_bits
            || static_cast<double>(rc.sumcheck.round_pow.difficulty()) > params.pow_bits;
    }

    std::printf("=========================================\n");
    std::printf("Whir (PCS) 🌪️\n");
    std::printf("Field: %s and hash: %s\n", args.field.c_str(), args.hash.c_str());
    std::printf("Security level: %.2f bits using %s decoding\n",
        config.security_level(config.initial_committer.num_vectors, args.num_evaluations),
        config.unique_decoding() ? "unique" : "list");
    std::printf("Source field: 64.00 bits, target field: %.2f bits\n",
        Target::field_size_bits);

    std::printf("Initial:\n");
    std::printf("  commit   size %zux%zu/%zu rate 2^-%.2f samples %zu in- %zu out-domain\n",
        config.initial_committer.num_vectors,
        config.initial_committer.vector_size,
        config.initial_committer.interleaving_depth,
        -std::log2(config.initial_committer.rate()),
        config.initial_committer.in_domain_samples,
        config.initial_committer.out_domain_samples);
    std::printf("  sumcheck size %zu rounds %zu pow %.2f\n",
        config.initial_sumcheck.initial_size,
        config.initial_sumcheck.num_rounds,
        static_cast<double>(config.initial_sumcheck.round_pow.difficulty()));

    for (std::size_t i = 0; i < config.round_configs.size(); ++i) {
        const auto& rc = config.round_configs[i];
        std::printf("Round %zu:\n", i);
        std::printf("  commit   size %zux%zu/%zu rate 2^-%.2f samples %zu in- %zu out-domain\n",
            rc.irs_committer.num_vectors,
            rc.irs_committer.vector_size,
            rc.irs_committer.interleaving_depth,
            -std::log2(rc.irs_committer.rate()),
            rc.irs_committer.in_domain_samples,
            rc.irs_committer.out_domain_samples);
        std::printf("  pow      %.2f bits\n", static_cast<double>(rc.pow.difficulty()));
        std::printf("  sumcheck size %zu rounds %zu pow %.2f\n",
            rc.sumcheck.initial_size,
            rc.sumcheck.num_rounds,
            static_cast<double>(rc.sumcheck.round_pow.difficulty()));
    }

    std::printf("Final:\n");
    std::printf("  pow      %.2fbits\n", static_cast<double>(config.final_pow.difficulty()));
    std::printf("  sumcheck size %zu rounds %zu pow %.2f\n",
        config.final_sumcheck.initial_size,
        config.final_sumcheck.num_rounds,
        static_cast<double>(config.final_sumcheck.round_pow.difficulty()));
    if (more_pow_bits_required) {
        std::printf("WARN: more PoW bits required than specified.\n");
    }
}

// WHIR PCS 基准测试主流程（按域类型 M 参数化）：
//   1. 构造测试向量 vector[i] = Source::from_u64(i)，即 f(x) = x 的多线性扩展
//   2. commit → prove → 导出 proof
//   3. 重复 verifier_repetitions 次 verify，统计平均验证时间与哈希次数
template <typename M>
void run_pcs(const Args& args) {
    using Source = typename M::Source;
    using Target = typename M::Target;
    namespace whir_ns = ::whir::protocols::whir;
    namespace tx = ::whir::transcript;
    namespace alg = ::whir::algebra;

    if (args.protocol_type != "PCS") {
        fail("only protocol type PCS is implemented in the C++ CLI");
    }
    if (args.soundness_type != "ConjectureList") {
        fail("only --sec ConjectureList is currently implemented in the C++ CLI");
    }
    if (args.fold_optimisation != "ProverHelps") {
        fail("only --fold_type ProverHelps is currently implemented in the C++ CLI");
    }
    if (args.num_variables >= 63) {
        fail("--num-variables is too large for this C++ CLI");
    }

    const std::size_t size = std::size_t{1} << args.num_variables;

    ::whir::ProtocolParameters params;
    params.security_level = args.security_level;
    params.pow_bits = args.pow_bits;
    params.initial_folding_factor = args.folding_factor;
    params.folding_factor = args.folding_factor;
    params.unique_decoding = false;
    params.starting_log_inv_rate = args.log_inv_rate;
    params.batch_size = 1;
    params.hash_id = hash_id_from_name(args.hash);

    auto config = whir_ns::Config<M>::from_params(size, params);
    print_config(args, params, config);

    // 构造测试多项式：f(x) = x（将索引 i 映射为域元素）
    std::vector<Source> vector(size);
    for (std::size_t i = 0; i < size; ++i) {
        vector[i] = Source::from_u64(static_cast<std::uint64_t>(i));
    }
    std::vector<std::span<const Source>> vec_spans{std::span<const Source>{vector}};

    M emb{};
    std::vector<std::unique_ptr<alg::LinearForm<Target>>> prove_linear_forms;
    std::vector<std::unique_ptr<alg::LinearForm<Target>>> verify_linear_forms;
    std::vector<Target> evaluations;
    prove_linear_forms.reserve(args.num_evaluations);
    verify_linear_forms.reserve(args.num_evaluations);
    evaluations.reserve(args.num_evaluations);

    // 为每个 evaluation 构造求值点（各维坐标均置为 e），
    // 用 MultilinearExtension 计算 f 在该点的值，供 prove/verify 使用。
    for (std::size_t e = 0; e < args.num_evaluations; ++e) {
        std::vector<Target> point(args.num_variables);
        for (auto& coord : point) {
            coord = Target::from_u64(static_cast<std::uint64_t>(e));
        }
        auto lf = std::make_unique<alg::MultilinearExtension<Target>>(point);
        evaluations.push_back(lf->template evaluate<M>(emb, std::span<const Source>{vector}));
        prove_linear_forms.push_back(std::move(lf));
        verify_linear_forms.push_back(std::make_unique<alg::MultilinearExtension<Target>>(std::move(point)));
    }

    auto ds = make_rust_cli_domain_separator(params);
    tx::Empty instance;

    auto t0 = Clock::now();
    auto ps = tx::ProverState::from_ds(ds, instance);
    auto witness = config.commit(ps, vec_spans);
    auto t_commit = Clock::now();

    std::vector<::whir::protocols::irs_commit::Witness<Source, Target>> whir_wits;
    whir_wits.push_back(std::move(witness));
    std::vector<std::span<const Source>> sp2{std::span<const Source>{vector}};

    config.prove(ps,
        sp2,
        std::span<const ::whir::protocols::irs_commit::Witness<Source, Target>>{whir_wits},
        std::move(prove_linear_forms),
        std::span<const Target>{evaluations});
    auto proof = std::move(ps).proof();
    auto t_prove = Clock::now();

    // 重置哈希计数器，仅统计 verify 阶段产生的哈希（排除 prove 阶段）
    ::whir::hash::hash_counter().reset();
    std::vector<const alg::LinearForm<Target>*> verify_linear_form_refs;
    verify_linear_form_refs.reserve(verify_linear_forms.size());
    for (const auto& lf : verify_linear_forms) {
        verify_linear_form_refs.push_back(lf.get());
    }

    auto tv0 = Clock::now();
    for (std::size_t rep = 0; rep < args.verifier_repetitions; ++rep) {
        auto vs = tx::VerifierState::from_ds(ds, instance, proof);
        auto comm = config.receive_commitment(vs);
        std::vector<const ::whir::protocols::irs_commit::Commitment<Target>*> cp{&comm};
        auto final_claim = config.verify(vs, cp, std::span<const Target>{evaluations});
        if (!final_claim.verify(verify_linear_form_refs)) {
            fail("verification failed");
        }
    }
    auto tv1 = Clock::now();

    const double commit_ms = std::chrono::duration<double, std::milli>(t_commit - t0).count();
    const double prove_ms = std::chrono::duration<double, std::milli>(t_prove - t_commit).count();
    const double verifier_ms =
        std::chrono::duration<double, std::milli>(tv1 - tv0).count()
        / static_cast<double>(args.verifier_repetitions);
    const double proof_kib =
        static_cast<double>(proof.narg_string.size() + proof.hints.size()) / 1024.0;
    const double avg_hashes_k =
        static_cast<double>(::whir::hash::hash_counter().get())
        / static_cast<double>(args.verifier_repetitions) / 1000.0;

    std::printf("\nProver time: %.1fms + %.1fms = %.1fms\n",
        commit_ms, prove_ms, commit_ms + prove_ms);
    std::printf("Proof size: %.1f KiB\n", proof_kib);
    std::printf("Verifier time: %.1fms\n", verifier_ms);
    std::printf("Average hashes: %.1fk\n", avg_hashes_k);
}

// 根据 --field 参数选择域与嵌入类型，实例化对应的 run_pcs 模板。
// Goldilocks1 → 基域直接运算，Goldilocks2/3 → 经 Basefield 嵌入到扩域。
int main(int argc, char* argv[]) {
    using namespace ::whir::algebra;

    Args args = parse_args(argc, argv);

    if (args.field == "Goldilocks1") {
        run_pcs<Identity<Goldilocks>>(args);
    } else if (args.field == "Goldilocks2") {
        run_pcs<Basefield<GoldilocksExt2>>(args);
    } else if (args.field == "Goldilocks3") {
        run_pcs<Basefield<GoldilocksExt3>>(args);
    } else {
        fail("unsupported field; expected Goldilocks1, Goldilocks2, or Goldilocks3");
    }

    return 0;
}
