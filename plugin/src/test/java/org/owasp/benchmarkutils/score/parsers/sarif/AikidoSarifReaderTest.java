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
 * PURPOSE. See the GNU General Public License for more details
 *
 * @author Henrique Cabral
 * @created 2026
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestHelper;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.parsers.ReaderTestBase;

class AikidoSarifReaderTest extends ReaderTestBase {

    private ResultFile resultFile;

    @BeforeEach
    void setUp() {
        resultFile = TestHelper.resultFileOf("testfiles/Benchmark_Aikido-1.0.0.sarif");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    void onlyAikidoSarifReaderReportsCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFile, AikidoSarifReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        AikidoSarifReader reader = new AikidoSarifReader();
        TestSuiteResults result = reader.parse(resultFile);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("Opengrep OSS", result.getToolName());
        assertEquals("1.0.0", result.getToolVersion());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.SQL_INJECTION, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.XSS, result.get(2).get(0).getCWE());
    }

    @Test
    void readerMapsCwes() {
        AikidoSarifReader reader = new AikidoSarifReader();

        assertEquals(CweNumber.WEAK_RANDOM, reader.mapCwe(330));
        assertEquals(CweNumber.WEAK_RANDOM, reader.mapCwe(338));
        assertEquals(CweNumber.WEAK_CRYPTO_ALGO, reader.mapCwe(327));
        assertEquals(CweNumber.WEAK_HASH_ALGO, reader.mapCwe(328));
        assertEquals(CweNumber.COMMAND_INJECTION, reader.mapCwe(78));
        assertEquals(CweNumber.SQL_INJECTION, reader.mapCwe(89));
        assertEquals(CweNumber.XSS, reader.mapCwe(79));
        assertEquals(CweNumber.LDAP_INJECTION, reader.mapCwe(90));
        assertEquals(CweNumber.XXE, reader.mapCwe(611));
        assertEquals(CweNumber.XPATH_INJECTION, reader.mapCwe(643));
        assertEquals(CweNumber.PATH_TRAVERSAL, reader.mapCwe(22));
        assertEquals(CweNumber.PATH_TRAVERSAL, reader.mapCwe(23));
        assertEquals(CweNumber.INSECURE_COOKIE, reader.mapCwe(614));
        assertEquals(CweNumber.COOKIE_WITHOUT_HTTPONLY, reader.mapCwe(1004));
    }
}
