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
package org.owasp.benchmarkutils.score.parsers;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

/**
 * Reader for Aikido Security JSON output (Opengrep native format).
 *
 * <p>Aikido Security (https://www.aikido.dev) is a commercial SAST/SCA platform powered by
 * Opengrep. When run directly, Opengrep produces a JSON report.
 *
 *
 * <p>To generate results for the OWASP Benchmark:
 *
 * <ol>
 *   <li><b>Cloud scan</b>: connect your GitHub repository to Aikido, trigger a scan, then export
 *       from the Aikido web UI.
 * </ol>
 *
 * <p>Name the output file {@code Benchmark_Aikido-&lt;version&gt;.json} before passing it to the
 * scoring tool.
 */
public class AikidoReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.isJson()
                && resultFile.json().has("results")
                && resultFile.json().has("errors")
                && "opengrep oss".equalsIgnoreCase(resultFile.json().optString("driver", "")); // or label or name or kitten or whatever
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Aikido Security", true, TestSuiteResults.ToolType.SAST);

        try {
            String version = resultFile.json().getString("version");
            tr.setToolVersion(version);
        } catch (JSONException e) {

        }

        tr.setTime(resultFile.file());

        JSONArray results = resultFile.json().getJSONArray("results");
        for (int i = 0; i < results.length(); i++) {
            TestCaseResult tcr = parseAikidoFinding(results.getJSONObject(i));
            if (tcr != null) {
                tr.put(tcr);
            }
        }
        return tr;
    }

    /**
     * TODO Should map AIKIDO Rule ID's 
     */
    public static int translate(int cwe) {
        switch (cwe) {
            case 11: 
            case 22: 
            case 23:
            case 35: 
                return CweNumber.PATH_TRAVERSAL;
            case 78:
                return CweNumber.COMMAND_INJECTION;
            case 79:
            case 80: // Basic XSS
                return CweNumber.XSS;
            case 89:
                return CweNumber.SQL_INJECTION;
            case 90:
                return CweNumber.LDAP_INJECTION;
            case 326:
            case 327:
            case 329:
            case 696:
                return CweNumber.WEAK_CRYPTO_ALGO;
            case 328:
                return CweNumber.WEAK_HASH_ALGO;
            case 330:
            case 338:
                return CweNumber.WEAK_RANDOM;
            case 501:
                return CweNumber.TRUST_BOUNDARY_VIOLATION;
            case 611:
                return CweNumber.XXE;
            case 614:
                return CweNumber.INSECURE_COOKIE;
            case 643:
                return CweNumber.XPATH_INJECTION;
            case 1004:
                return CweNumber.COOKIE_WITHOUT_HTTPONLY;
            default:
                System.out.println(
                        "INFO: Found following CWE in Aikido results which we haven't seen before: "
                                + cwe);
        }
        return cwe;
    }


// TODO -> properly convert AIK Sarif
    private TestCaseResult parseAikidoFinding(JSONObject result) {
        try {
            String className = result.getString("path");
            className = (className.substring(className.lastIndexOf('/') + 1)).split("\\.")[0];

            if (className.startsWith(BenchmarkScore.TESTCASENAME)) {
                TestCaseResult tcr = new TestCaseResult();

                //JSONObject extra = result.getJSONObject("extra");
                //JSONObject metadata = extra.getJSONObject("metadata");

                // CWE — stored as a string e.g. "CWE-89: SQL Injection ..."
                String cweString = getStringOrFirstArrayIndex(metadata, "cwe");
                int cwe = Integer.parseInt(cweString.split(":")[0].split("-")[1]);

                try {
                    cwe = translate(cwe);
                } catch (NumberFormatException ex) {
                    System.out.println("CWE # not parseable from: " + metadata.getString("cwe"));
                }

                String category = getStringOrFirstArrayIndex(metadata, "owasp");
                String evidence = result.getString("check_id");

                tcr.setCWE(cwe);
                tcr.setCategory(category);
                tcr.setEvidence(evidence);
                tcr.setConfidence(0);
                tcr.setNumber(testNumber(className));

                return tcr;
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private static String getStringOrFirstArrayIndex(JSONObject metadata, String key) {
        if (metadata.get(key) instanceof JSONArray) {
            return metadata.getJSONArray(key).getString(0);
        } else {
            return metadata.getString(key);
        }
    }
}
