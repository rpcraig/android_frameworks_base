package gov.android.selinux.unit;

import android.os.Process;
import android.test.AndroidTestCase;
import android.util.Log;
import gov.android.selinux.SELinuxCommon;

public class SELinuxUnitTest extends AndroidTestCase {

    public static final String TAG="SELinuxUnitTest";

    public void testisSELinuxEnabled() {
	boolean ret = SELinuxCommon.isSELinuxEnabled();
	Log.i(TAG, "isSELinuxEnabled: " + ret);
    }

    public void testgetSELinuxEnforce() {
	boolean ret = SELinuxCommon.getSELinuxEnforce();
	Log.i(TAG, "SELinux enforce: " + ret);
    }

    public void testgetFileCon() {
	String ctx;
	ctx = SELinuxCommon.getFileCon("/system/bin/toolbox");
	Log.i(TAG, "getFileCon: " + ctx);
    }

    public void testgetCon() {
	String mycon = SELinuxCommon.getCon();
	Log.i(TAG, "getCon: " + mycon);
    }

    public void testgetPidCon() {
	String mycon = SELinuxCommon.getPidCon(Process.myPid());
	Log.i(TAG, "getPidCon: " + mycon);
    }

    public void testcheckSELinuxAccess() {
	String mycon = SELinuxCommon.getCon();
	boolean ret;
	ret = SELinuxCommon.checkSELinuxAccess(mycon, mycon, "process", "fork");
	Log.i(TAG, "checkSELinuxAccess process fork: " + ret);
	ret = SELinuxCommon.checkSELinuxAccess(mycon, mycon, "memprotect", "mmap_zero");
	Log.i(TAG, "checkSELinuxAccess memprotect mmap_zero: " + ret);
    }
}
