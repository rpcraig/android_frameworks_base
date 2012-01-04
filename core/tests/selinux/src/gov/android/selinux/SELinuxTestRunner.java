package gov.android.selinux;

import junit.framework.TestSuite;

import android.test.InstrumentationTestRunner;
import android.test.InstrumentationTestSuite;

/**
 * Instrumentation Test Runner for all SELinux unit tests.
 *
 * Running all tests:
 *
 *   runtest selinux
 * or
 *   m selinuxframeworktest && adb install -r $ANDROID_BUILD_TOP/cout/target/product/crespo4g/data/app/selinuxframeworktest.apk
 *   adb shell am instrument -w gov.android.selinux/.SELinuxTestRunner
 */

public class SELinuxTestRunner extends InstrumentationTestRunner {

    @Override
    public TestSuite getAllTests() {
        TestSuite suite = new InstrumentationTestSuite(this);
        suite.addTestSuite(gov.android.selinux.unit.SELinuxUnitTest.class);
	// suite.addTestSuite(gov.android.selinux.unit.SELinuxNewTestSuiteHere.class);
	// suite.addTestSuite(gov.android.selinux.power.SELinuxNewTestSuiteHere.class);
        return suite;
    }

    @Override
    public ClassLoader getLoader() {
        return SELinuxTestRunner.class.getClassLoader();
    }
}
