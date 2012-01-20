package android.os;

import java.io.FileDescriptor;

/**
 * This class provides access to the centralized jni bindings for
 * SELinux interaction.
 * {@hide}
 */
public class SELinux {

    /**
     * Determine whether SELinux is disabled or enabled.
     * @return a boolean indicating whether SELinux is enabled.
     */
    public static final native boolean isSELinuxEnabled();

    /**
     * Determine whether SELinux is permissive or enforcing.
     * @return a boolean indicating whether SELinux is enforcing.
     */
    public static final native boolean isSELinuxEnforced();

    /**
     * Sets the security context for newly created file objects.
     * @param context a security context given as a String.
     * @return a boolean indicating whether the operation succeeded.
     */
    public static final native boolean setFSCreateContext(String context);

    /**
     * Change the security context of an existing file object.
     * @param path representing the path of file object to relabel.
     * @param con new security context given as a String.
     * @return a boolean indicating whether the operation succeeded.
     */
    public static final native boolean setFileContext(String path, String context);

    /**
     * Get the security context of a file object.
     * @param path the pathname of the file object.
     * @return a security context given as a String.
     */
    public static final native String getFileContext(String path);

    /**
     * Get the security context of a peer socket.
     * @param fd FileDescriptor class of the peer socket.
     * @return a String representing the peer socket security context.
     */
    public static final native String getPeerContext(FileDescriptor fd);

    /**
     * Gets the security context of the current process.
     * @return a String representing the security context of the current process.
     */
    public static final native String getContext();

    /**
     * Gets the security context of a given process id.
     * Use of this function is discouraged for Binder transactions.
     * Use Binder.getCallingSecctx() instead.
     * @param pid an int representing the process id to check.
     * @return a String representing the security context of the given pid.
     */
    public static final native String getPidContext(int pid);

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
