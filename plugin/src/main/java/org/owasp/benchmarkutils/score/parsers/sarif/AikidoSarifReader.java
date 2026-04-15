/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Henrique Cabral
 * @created 2026
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import org.owasp.benchmarkutils.score.parsers.AikidoReader;

/**
 * Reader for Aikido Security SARIF output (Opengrep SARIF format).
 *
 * <p>Aikido Security (https://www.aikido.dev) is a commercial SAST/SCA platform powered by
 * Opengrep.
 *
 * <p>To generate results for the OWASP Benchmark:
 *
 * <ol>
 *   <li><b>Cloud scan</b>: connect your GitHub repository to Aikido, trigger a scan, then export
 *       the SARIF from the Aikido web UI (Scans → export as SARIF).
 * </ol>
 *
 * <p>Name the exported file {@code Benchmark_Aikido-&lt;version&gt;.sarif} before passing it to
 * the scoring tool.
 */
public class AikidoSarifReader extends SarifReader {

    public AikidoSarifReader() {
        super("Opengrep OSS", true, CweSourceType.TAG);
    }

    @Override
    public int mapCwe(int cwe) {
        return AikidoReader.translate(cwe);
    }
}
