package gov.android.selinux;

import android.util.Config;
import android.util.Log;
import java.io.FileDescriptor;

/**
 * This class provides access to the centralized jni bindings for
 * SELinux interaction.
 */
public class SELinuxCommon {

    /**
     * Logcat tagging variable
     */
    private static final String TAG = "SELinuxCommon";

    /**
     * Determine whether SELinux is disabled or enabled.
     * @param none
     * @return a boolean representing whether SELinux is enabled
     */
    public static final native boolean isSELinuxEnabled();

    /**
     * Determine whether SELinux is permissive or enforcing.
     * @param none
     * @return a boolean representing whether SELinux is enforcing
     */
    public static final native boolean getSELinuxEnforce();


    /**
     * Sets the security context to use for newly created files and
     * directories.
     * @param context a security context String
     * @return a boolean indicating whether the operation succeeded
     * @exceptions None
     */
    public static final native boolean setFSCreateCon(String context);

    /**
     * Change the security context of an existing file to a new value.
     * @param path path of file to relabel
     * @param con new security context
     * @return a boolean indicating whether the operation succeeded
     */
    public static final native boolean setFileCon(String path, String con);

    /**
     * Get the security context of a file.
     * @param path the pathname of the file
     * @returns a security context String
     */
    public static final native String getFileCon(String path);
    
    /**
     * Get the security context of a peer socket
     * @param fd FileDescriptor class of the peer socket
     * @return a String populated with the peer socket security context
     */
    public static final native String getPeerCon(FileDescriptor fd);

    /**
     * Gets the security context of the current process.
     * @param none
     * @returns a String
     * @exceptions None
     */
    public static final native String getCon();

    /**
     * Gets the security context of a given process id.
     * Use of this function is discouraged for Binder transactions.
     * Use Binder.getCallingSecctx() instead.
     * @param pid an int representing the process id to check
     * @returns a String
     * @exceptions None
     */
    public static final native String getPidCon(int pid);

    /**
     * Check permissions between two security contexts.
     * @param scon The source or subject security context.
     * @param tcon The target or object security context.
     * @param tclass The object security class name.
     * @param perm The permission name.
     * @return a boolean indicating whether permission was granted.
     */
    public static final native boolean checkSELinuxAccess(String scon, String tcon, String tclass, String perm);
}
