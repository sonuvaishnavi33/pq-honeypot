package pqh.research;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;

/**
 * Key-establishment comparison for the "cost of post-quantum" table.
 * Needs JDK 24+ for ML-KEM (JEP 496); on older JDKs that row is reported as unavailable.
 * Usage: java pqh.research.KemBenchmark [runs] [iterationsPerRun] [warmup]
 */
public final class KemBenchmark {
    @FunctionalInterface
    private interface Op { void run() throws Exception; }

    private record Row(String scheme, String operation, double meanMs, double ciLow, double ciHigh,
                       int keyBytes, int payloadBytes, int wireBytes) {}

    private record Sample(String scheme, String operation, int run, double meanMs) {}

    public static void main(String[] args) throws IOException {
        ResearchConfigLoader.Settings settings = ResearchConfigLoader.load();
        ResearchProperties.Benchmark benchmark = settings.research().benchmark();
        int runs = args.length > 0 ? Integer.parseInt(args[0]) : benchmark.runs();
        int iterations = args.length > 1 ? Integer.parseInt(args[1]) : benchmark.iterationsPerRun();
        int warmup = args.length > 2 ? Integer.parseInt(args[2]) : benchmark.warmup();
        long seed = args.length > 3 ? Long.parseLong(args[3]) : settings.research().seed();
        int bootstrapResamples = args.length > 4 ? Integer.parseInt(args[4]) : benchmark.bootstrapResamples();
        List<Row> rows = new ArrayList<>();
        List<Sample> samples = new ArrayList<>();

        attempt("X25519", () -> ecdh("X25519", null, "X25519", rows, samples, runs, iterations,
                warmup, bootstrapResamples, seed));
        attempt("ECDH-P256", () -> ecdh("EC", new ECGenParameterSpec("secp256r1"), "ECDH", rows,
                samples, runs, iterations, warmup, bootstrapResamples, seed));
        attempt("ML-KEM-768", () -> mlKem(rows, samples, runs, iterations, warmup, bootstrapResamples, seed));
        attempt("RSA-2048-OAEP", () -> rsa(rows, samples, runs, iterations, warmup, bootstrapResamples, seed));
        attempt("ML-DSA-65", () -> mlDsa(rows, samples, runs, iterations, warmup, bootstrapResamples, seed));

        StringBuilder summary = new StringBuilder(
                "scheme,operation,mean_ms,ci95_low_ms,ci95_high_ms,key_bytes,payload_bytes,wire_bytes,runs,iterations_per_run,warmup,bootstrap_seed\n");
        for (Row r : rows) {
            summary.append(String.format(Locale.ROOT, "%s,%s,%.5f,%.5f,%.5f,%d,%d,%d,%d,%d,%d,%d%n",
                    r.scheme, r.operation, r.meanMs, r.ciLow, r.ciHigh, r.keyBytes, r.payloadBytes,
                    r.wireBytes, runs, iterations, warmup, seed));
        }
        Path out = Path.of(settings.research().outputDir(), "kem_micro.csv");
        Files.createDirectories(out.getParent());
        Files.writeString(out, summary.toString());
        StringBuilder raw = new StringBuilder("scheme,operation,run,mean_ms\n");
        for (Sample sample : samples) {
            raw.append(String.format(Locale.ROOT, "%s,%s,%d,%.8f%n",
                    sample.scheme, sample.operation, sample.run, sample.meanMs));
        }
        Files.writeString(out.resolveSibling("kem_micro_samples.csv"), raw.toString());
        System.out.println(summary);
        System.out.println("Summary CSV: " + out.toAbsolutePath());
        System.out.println("Raw samples CSV: " + out.resolveSibling("kem_micro_samples.csv").toAbsolutePath());
    }

    private static void attempt(String name, Op op) {
        try {
            op.run();
        } catch (Exception | LinkageError e) {
            System.err.println(name + " unavailable on this JDK: " + e.getMessage());
        }
    }

    private static void ecdh(String keyAlg, ECGenParameterSpec spec, String agreement, List<Row> rows,
                             List<Sample> samples, int runs, int iterations, int warmup,
                             int bootstrapResamples, long seed) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlg);
        if (spec != null) generator.initialize(spec);
        KeyPair local = generator.generateKeyPair();
        KeyPair peer = generator.generateKeyPair();
        String name = keyAlg.equals("EC") ? "ECDH-P256" : keyAlg;
        int keyBytes = peer.getPublic().getEncoded().length;
        rows.add(measure(name, "keygen", runs, iterations, warmup, generator::generateKeyPair, keyBytes, 0,
                keyBytes, bootstrapResamples, seed, samples));
        rows.add(measure(name, "agree", runs, iterations, warmup, () -> {
            KeyAgreement ka = KeyAgreement.getInstance(agreement);
            ka.init(local.getPrivate());
            ka.doPhase(peer.getPublic(), true);
            ka.generateSecret();
        }, keyBytes, 32, keyBytes, bootstrapResamples, seed, samples));
    }

    private static void mlKem(List<Row> rows, List<Sample> samples, int runs, int iterations, int warmup,
                              int bootstrapResamples, long seed) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-KEM-768");
        KeyPair pair = generator.generateKeyPair();
        KEM kem = KEM.getInstance("ML-KEM");
        KEM.Encapsulated sample = kem.newEncapsulator(pair.getPublic()).encapsulate();
        int keyBytes = pair.getPublic().getEncoded().length;
        int encapsulationBytes = sample.encapsulation().length;
        rows.add(measure("ML-KEM-768", "keygen", runs, iterations, warmup, generator::generateKeyPair,
                keyBytes, 0, keyBytes, bootstrapResamples, seed, samples));
        rows.add(measure("ML-KEM-768", "encapsulate", runs, iterations, warmup,
                () -> kem.newEncapsulator(pair.getPublic()).encapsulate(), keyBytes, encapsulationBytes,
                encapsulationBytes, bootstrapResamples, seed, samples));
        rows.add(measure("ML-KEM-768", "decapsulate", runs, iterations, warmup,
                () -> kem.newDecapsulator(pair.getPrivate()).decapsulate(sample.encapsulation()), keyBytes,
                encapsulationBytes, encapsulationBytes, bootstrapResamples, seed, samples));
    }

    private static void rsa(List<Row> rows, List<Sample> samples, int runs, int iterations, int warmup,
                            int bootstrapResamples, long seed) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        byte[] secret = new byte[32];
        Cipher enc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        enc.init(Cipher.ENCRYPT_MODE, pair.getPublic());
        byte[] wrapped = enc.doFinal(secret);
        int keyBytes = pair.getPublic().getEncoded().length;
        rows.add(measure("RSA-2048-OAEP", "encrypt", runs, iterations, warmup, () -> {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.ENCRYPT_MODE, pair.getPublic());
            c.doFinal(secret);
        }, keyBytes, wrapped.length, wrapped.length, bootstrapResamples, seed, samples));
        rows.add(measure("RSA-2048-OAEP", "decrypt", runs, iterations, warmup, () -> {
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            c.init(Cipher.DECRYPT_MODE, pair.getPrivate());
            c.doFinal(wrapped);
        }, keyBytes, wrapped.length, wrapped.length, bootstrapResamples, seed, samples));
    }

    private static void mlDsa(List<Row> rows, List<Sample> samples, int runs, int iterations, int warmup,
                              int bootstrapResamples, long seed) throws Exception {
        KeyPair pair = CheckpointSigner.generate();
        byte[] message = CheckpointSigner.message("benchmark-node", 1, "0123456789abcdef", 1L);
        byte[] signed = CheckpointSigner.sign(pair.getPrivate(), "benchmark-node", 1,
                "0123456789abcdef", 1L);
        int keyBytes = pair.getPublic().getEncoded().length;
        rows.add(measure("ML-DSA-65", "keygen", runs, iterations, warmup,
                () -> CheckpointSigner.generate(), keyBytes, 0, keyBytes,
                bootstrapResamples, seed, samples));
        rows.add(measure("ML-DSA-65", "sign", runs, iterations, warmup,
                () -> CheckpointSigner.sign(pair.getPrivate(), "benchmark-node", 1,
                        "0123456789abcdef", 1L), keyBytes, signed.length, signed.length,
                bootstrapResamples, seed, samples));
        rows.add(measure("ML-DSA-65", "verify", runs, iterations, warmup, () -> {
            Signature verifier = Signature.getInstance("ML-DSA");
            verifier.initVerify(pair.getPublic());
            verifier.update(message);
            verifier.verify(signed);
        }, keyBytes, signed.length, signed.length, bootstrapResamples, seed, samples));
    }

    private static Row measure(String scheme, String operation, int runs, int iterations, int warmup, Op op,
                               int keyBytes, int payloadBytes, int wireBytes, int bootstrapResamples, long seed,
                               List<Sample> samples)
            throws Exception {
        for (int i = 0; i < warmup; i++) op.run();
        double[] perRunMs = new double[runs];
        for (int r = 0; r < runs; r++) {
            long start = System.nanoTime();
            for (int i = 0; i < iterations; i++) op.run();
            perRunMs[r] = (System.nanoTime() - start) / 1e6 / iterations;
            samples.add(new Sample(scheme, operation, r + 1, perRunMs[r]));
        }
        double[] ci = Stats.bootstrapMeanCi(perRunMs, 0.95, bootstrapResamples,
                seed ^ ((long) scheme.hashCode() << 32) ^ operation.hashCode());
        return new Row(scheme, operation, Stats.mean(perRunMs), ci[0], ci[1],
                keyBytes, payloadBytes, wireBytes);
    }
}
