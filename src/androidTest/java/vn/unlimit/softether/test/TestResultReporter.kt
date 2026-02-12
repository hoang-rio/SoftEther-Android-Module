package vn.unlimit.softether.test

import android.content.Context
import android.util.Log
import vn.unlimit.softether.test.model.NativeTestResult
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Reporter for test results that can output to logs and files
 */
class TestResultReporter(private val context: Context) {

    companion object {
        private const val TAG = "TestResultReporter"
        private const val REPORT_DIR = "test_reports"
        private const val MAX_REPORT_FILES = 10
    }

    private val reportBuffer = StringBuilder()
    private val testResults = mutableListOf<TestCaseResult>()
    private var testStartTime: Long = 0

    /**
     * Start a new test run
     */
    fun startTestRun() {
        testStartTime = System.currentTimeMillis()
        reportBuffer.clear()
        testResults.clear()

        appendHeader()
        Log.d(TAG, "Test run started")
    }

    /**
     * Record a test result
     */
    fun recordTest(
        testName: String,
        result: NativeTestResult,
        serverInfo: String = ""
    ) {
        val testCaseResult = TestCaseResult(
            name = testName,
            success = result.success,
            errorCode = result.errorCode,
            errorMessage = result.errorMessage,
            durationMs = result.connectTimeMs,
            serverInfo = serverInfo,
            timestamp = System.currentTimeMillis()
        )

        testResults.add(testCaseResult)

        // Log result
        val status = if (result.success) "✓ PASS" else "✗ FAIL"
        Log.d(TAG, "$status: $testName - ${result.errorMessage} (${result.connectTimeMs}ms)")

        // Append to report
        reportBuffer.append("\n## Test: $testName\n")
        reportBuffer.append("- Status: $status\n")
        reportBuffer.append("- Duration: ${result.connectTimeMs}ms\n")
        if (serverInfo.isNotEmpty()) {
            reportBuffer.append("- Server: $serverInfo\n")
        }
        if (!result.success) {
            reportBuffer.append("- Error Code: ${result.errorCode}\n")
            reportBuffer.append("- Error: ${result.errorMessage}\n")
        }
        reportBuffer.append("- Timestamp: ${formatTimestamp(testCaseResult.timestamp)}\n")
    }

    /**
     * Record a test error
     */
    fun recordTestError(testName: String, error: Throwable, serverInfo: String = "") {
        val testCaseResult = TestCaseResult(
            name = testName,
            success = false,
            errorCode = NativeTestResult.ERROR_UNKNOWN,
            errorMessage = error.message ?: "Unknown error",
            durationMs = 0,
            serverInfo = serverInfo,
            timestamp = System.currentTimeMillis()
        )

        testResults.add(testCaseResult)

        Log.e(TAG, "✗ ERROR: $testName - ${error.message}", error)

        reportBuffer.append("\n## Test: $testName\n")
        reportBuffer.append("- Status: ✗ ERROR\n")
        if (serverInfo.isNotEmpty()) {
            reportBuffer.append("- Server: $serverInfo\n")
        }
        reportBuffer.append("- Error: ${error.message}\n")
        reportBuffer.append("- Timestamp: ${formatTimestamp(testCaseResult.timestamp)}\n")
    }

    /**
     * End test run and generate summary
     */
    fun endTestRun(): TestRunSummary {
        val totalDuration = System.currentTimeMillis() - testStartTime
        val passed = testResults.count { it.success }
        val failed = testResults.size - passed

        val summary = TestRunSummary(
            totalTests = testResults.size,
            passedTests = passed,
            failedTests = failed,
            totalDurationMs = totalDuration,
            testResults = testResults.toList()
        )

        appendFooter(summary)

        Log.d(TAG, "Test run completed: $passed/${testResults.size} passed in ${totalDuration}ms")

        return summary
    }

    /**
     * Save report to file
     */
    fun saveReport(): File? {
        return try {
            val reportDir = File(context.getExternalFilesDir(null), REPORT_DIR)
            if (!reportDir.exists()) {
                reportDir.mkdirs()
            }

            // Clean up old reports
            cleanupOldReports(reportDir)

            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val reportFile = File(reportDir, "softether_test_report_$timestamp.md")

            reportFile.writeText(reportBuffer.toString())
            Log.d(TAG, "Test report saved to: ${reportFile.absolutePath}")

            reportFile
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save test report", e)
            null
        }
    }

    /**
     * Get the current report as string
     */
    fun getReport(): String = reportBuffer.toString()

    private fun appendHeader() {
        reportBuffer.append("# SoftEther VPN Native Test Report\n")
        reportBuffer.append("Generated: ${formatTimestamp(System.currentTimeMillis())}\n")
        reportBuffer.append("Device: ${android.os.Build.MODEL}\n")
        reportBuffer.append("Android: ${android.os.Build.VERSION.RELEASE}\n")
        reportBuffer.append("---\n")
    }

    private fun appendFooter(summary: TestRunSummary) {
        reportBuffer.append("\n---\n")
        reportBuffer.append("## Summary\n")
        reportBuffer.append("- Total Tests: ${summary.totalTests}\n")
        reportBuffer.append("- Passed: ${summary.passedTests}\n")
        reportBuffer.append("- Failed: ${summary.failedTests}\n")
        reportBuffer.append("- Success Rate: ${summary.successRate}%\n")
        reportBuffer.append("- Total Duration: ${summary.totalDurationMs}ms\n")
    }

    private fun cleanupOldReports(reportDir: File) {
        try {
            val files = reportDir.listFiles { file ->
                file.name.startsWith("softether_test_report_") && file.name.endsWith(".md")
            }?.sortedBy { it.lastModified() } ?: return

            if (files.size > MAX_REPORT_FILES) {
                files.take(files.size - MAX_REPORT_FILES).forEach { it.delete() }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to cleanup old reports", e)
        }
    }

    private fun formatTimestamp(timestamp: Long): String {
        return SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(Date(timestamp))
    }
}

/**
 * Data class representing a single test case result
 */
data class TestCaseResult(
    val name: String,
    val success: Boolean,
    val errorCode: Int,
    val errorMessage: String,
    val durationMs: Long,
    val serverInfo: String,
    val timestamp: Long
)

/**
 * Summary of a test run
 */
data class TestRunSummary(
    val totalTests: Int,
    val passedTests: Int,
    val failedTests: Int,
    val totalDurationMs: Long,
    val testResults: List<TestCaseResult>
) {
    val successRate: Float
        get() = if (totalTests > 0) (passedTests.toFloat() / totalTests * 100) else 0f

    fun toSummaryString(): String {
        return buildString {
            append("Test Run Summary: ")
            append("$passedTests/$totalTests passed")
            append(" (${String.format("%.1f", successRate)}%)")
            append(" in ${totalDurationMs}ms")
            if (failedTests > 0) {
                append(" - $failedTests FAILED")
            }
        }
    }
}
