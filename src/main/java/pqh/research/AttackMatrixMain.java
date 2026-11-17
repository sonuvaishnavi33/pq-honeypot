package pqh.research;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import pqh.research.AttackMatrix.Row;

/**
 * Runs every attack in every integrity mode and writes one CSV.
 * Usage: java pqh.research.AttackMatrixMain [trials=200] [seed=42] [csvPath=results/reference_attack_matrix.csv]
 * This runner uses ReferenceTarget; its output is a semantic model result, not a live-service measurement.
 */
public final class AttackMatrixMain {
    public static void main(String[] args) throws IOException {
        ResearchProperties properties = ResearchConfigLoader.load().research();
        int trials = args.length > 0 ? Integer.parseInt(args[0]) : properties.trials();
        long seed = args.length > 1 ? Long.parseLong(args[1]) : properties.seed();
        Path out = Path.of(args.length > 2 ? args[2]
                : properties.outputDir() + "/reference_attack_matrix.csv");

        EvidenceTarget target = new ReferenceTarget();
        StringBuilder csv = new StringBuilder();
        List<List<Row>> perMode = new ArrayList<>();
        for (IntegrityMode mode : IntegrityMode.values()) {
            List<Row> rows = AttackMatrix.run(Attacks.all(target, mode), trials, seed);
            perMode.add(rows);
            String block = AttackMatrix.toCsv("REFERENCE_MODEL", mode.name(), rows);
            csv.append(csv.length() == 0 ? block : block.substring(block.indexOf('\n') + 1));
        }
        if (out.getParent() != null) Files.createDirectories(out.getParent());
        Files.writeString(out, csv.toString());

        System.out.printf(Locale.ROOT, "%-42s", "attack \\ mode");
        for (IntegrityMode m : IntegrityMode.values()) System.out.printf(Locale.ROOT, "%14s", m);
        System.out.println();
        for (int a = 0; a < perMode.get(0).size(); a++) {
            System.out.printf(Locale.ROOT, "%-42s", perMode.get(0).get(a).attack());
            for (List<Row> rows : perMode) {
                Row r = rows.get(a);
                String cell = r.trials() == 0 ? "n/a" : String.format(Locale.ROOT, "%.0f%%", r.rate() * 100);
                System.out.printf(Locale.ROOT, "%14s", r.errors() > 0 ? cell + "(err)" : cell);
            }
            System.out.println();
        }
        System.out.println("CSV written to " + out);
    }
}
