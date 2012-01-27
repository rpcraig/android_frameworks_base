#define LOG_TAG "SELinuxJNI"
#include <utils/Log.h>

#include "JNIHelp.h"
#include "jni.h"
#include "android_runtime/AndroidRuntime.h"
#ifdef HAVE_SELINUX
#include "selinux/selinux.h"
#endif
#include <errno.h>

namespace android {
  static void throw_NullPointerException(JNIEnv *env, const char* msg) {
    jclass clazz;
    clazz = env->FindClass("java/lang/NullPointerException");
    env->ThrowNew(clazz, msg);
  }

  /*
   * Function: isSELinuxEnabled
   * Purpose:  checks whether SELinux is enabled/disbaled
   * Parameters: none
   * Return value : true (enabled) or false (disabled)
   * Exceptions: none
   */
  static jboolean isSELinuxEnabled(JNIEnv *env, jobject classz) {
#ifdef HAVE_SELINUX
    int seLinuxEnabled = is_selinux_enabled();
    if(seLinuxEnabled == -1) {
      LOGE("Error retrieving SELinux enabled status (%s)", strerror(errno));
    }

    LOGV("is_selinux_enabled returned %d", seLinuxEnabled);

    return (seLinuxEnabled == 1) ? true : false;
#else
    return false;
#endif
  }

  /*
   * Function: isSELinuxEnforced
   * Purpose: return the current SELinux enforce mode
   * Parameters: none
   * Return value: true (enforcing) or false (permissive)
   * Exceptions: none
   */
  static jboolean isSELinuxEnforced(JNIEnv *env, jobject clazz) {
#ifdef HAVE_SELINUX
    int seLinuxEnforce = security_getenforce();
    if(seLinuxEnforce == -1) {
      LOGE("Error retrieving SELinux enforce mode (%s)", strerror(errno));
    }

    LOGV("security_getenforce returned %d", seLinuxEnforce);

    return (seLinuxEnforce == 1) ? true : false;
#else
    return false;
#endif
  }

  /*
   * Function: getPeerCon
   * Purpose: retrieves security context of peer socket
   * Parameters:
   *        fileDescriptor: peer socket file as a FileDescriptor object
   * Returns: jstring representing the security_context of socket or NULL if error
   * Exceptions: NullPointerException if fileDescriptor object is NULL
   */
  static jstring getPeerCon(JNIEnv *env, jobject clazz, jobject fileDescriptor) {
#ifdef HAVE_SELINUX
    if(fileDescriptor == NULL) {
      throw_NullPointerException(env, "Trying to check security context of a null peer socket.");
      return NULL;
    }

    security_context_t context = NULL;
    jstring securityString = NULL;
    int peercon_return;

    int fd = jniGetFDFromFileDescriptor(env, fileDescriptor);

    if (env->ExceptionOccurred() != NULL) {
      LOGE("There was an issue with retrieving the file descriptor");
      goto bail;
    }

    peercon_return = getpeercon(fd, &context);

    if(peercon_return == -1) {
      LOGE("getPeerCon: Error retrieving context of peer connection (%s)", strerror(errno));
      goto bail;
    }

    LOGV("getPeerCon: Successfully retrived context of peer socket '%s'", context);

    securityString = env->NewStringUTF(context);

  bail:
    if(context != NULL)
      freecon(context);

    return securityString;
#else
    return NULL;
#endif
  }

  /*
   * Function: setFSCreateCon
   * Purpose: set security context used for creating a new file system object
   * Parameters:
   *       context: security_context_t representing the new context of a file system object,
   *                set to NULL to return to the default policy behavior
   * Returns: true on success, false on error
   * Exception: none
   */
  static jboolean setFSCreateCon(JNIEnv *env, jobject clazz, jstring context) {
#ifdef HAVE_SELINUX
    char * securityContext = NULL;
    const char *constant_securityContext = NULL;

    if(context != NULL) {
      constant_securityContext = env->GetStringUTFChars(context, NULL);

      // GetStringUTFChars returns const char * yet setfscreatecon needs char *
      securityContext = const_cast<char *>(constant_securityContext);
    }

    int ret = setfscreatecon(securityContext);
    if(ret == -1) {
      const char * tmp = (context == NULL) ? "default" : securityContext;
      LOGE("setFSCreateCon: error with setting security context -> '%s' (%s)", tmp, strerror(errno));
      goto bail;
    }

    LOGV("setFSCreateCon: set new security context to '%s' ", context == NULL ? "default", context);

  bail:
    if(constant_securityContext != NULL)
      env->ReleaseStringUTFChars(context, constant_securityContext);

    return (ret == 0) ? true : false;
#else
    return false;
#endif
  }

  /*
   * Function: setFileCon
   * Purpose:  set the security context of a file object
   * Parameters:
   *       path: the location of the file system object
   *       con: the new security context of the file system object
   * Returns: 0 on success, -1 on error
   * Exception: NullPointerException is thrown if either path or context strign are NULL
   */
  static jboolean setFileCon(JNIEnv *env, jobject clazz, jstring path, jstring con) {
#ifdef HAVE_SELINUX
    if(path == NULL) {
      throw_NullPointerException(env, "Trying to change the security context of a NULL file object.");
      return false;
    }

    if(con == NULL) {
      throw_NullPointerException(env, "Trying to set the security context of a file object with NULL.");
      return false;
    }

    const char *objectPath = env->GetStringUTFChars(path, NULL);
    const char *constant_con = env->GetStringUTFChars(con, NULL);

    // GetStringUTFChars returns const char * yet setfilecon needs char *
    char * newCon = const_cast<char *>(constant_con);

    int ret = setfilecon(objectPath, newCon);
    if(ret == -1) {
      LOGE("setFileCon: Error setting security context '%s' for '%s' (%s)", newCon, objectPath, strerror(errno));
      goto bail;
    }

    LOGV("setFileCon: Succesfully set security context '%s' for '%s'", newCon, objectPath);

  bail:
    env->ReleaseStringUTFChars(path, objectPath);
    env->ReleaseStringUTFChars(con, constant_con);
    return (ret == 0) ? true : false;
#else
    return false;
#endif
  }

  /*
   * Function: getFileCon
   * Purpose: retrieves the context associated with the given path in the file system
   * Parameters:
   *        path: given path in the file system
   * Returns:
   *        string representing the security context string of the file object
   *        the string may be NULL if an error occured
   * Exceptions: NullPointerException if the path object is null
   */
  static jstring getFileCon(JNIEnv *env, jobject clazz, jstring path) {
#ifdef HAVE_SELINUX
    if(path == NULL) {
      throw_NullPointerException(env, "Trying to check security context of a null path.");
      return NULL;
    }

    const char *objectPath = env->GetStringUTFChars(path, NULL);

    security_context_t context = NULL;
    jstring securityString = NULL;

    int ret = getfilecon(objectPath, &context);
    if(ret == -1) {
      LOGE("getFileCon: Error retrieving context of file '%s' (%s)", objectPath, strerror(errno));
      goto bail;
    }

    LOGV("getFileCon: Successfully retrived context '%s' for file '%s'", context, objectPath);

    securityString = env->NewStringUTF(context);

  bail:
    if(context != NULL)
      freecon(context);

    env->ReleaseStringUTFChars(path, objectPath);

    return securityString;
#else
    return NULL;
#endif
  }

  /*
   * Function: getCon
   * Purpose: Get the context of the current process.
   * Parameters: none
   * Returns: a jstring representing the security context of the process,
   *          the jstring may be NULL if there was an error
   * Exceptions: none
   */
  static jstring getCon(JNIEnv *env, jobject clazz) {
#ifdef HAVE_SELINUX
    security_context_t context = NULL;
    jstring securityString = NULL;

    if(getcon(&context) == -1) {
      LOGE("getCon: Error retrieving own context: (%s)", strerror(errno));
      goto bail;
    }

    LOGV("getCon: Successfully retrieved context '%s'", context);

    securityString = env->NewStringUTF(context);

  bail:
    if(context != NULL)
      freecon(context);

    return securityString;
#else
    return NULL;
#endif
  }

  /*
   * Function: getPidCon
   * Purpose: Get the context of a process identified by its pid
   * Parameters:
   *            pid: a jint representing the process
   * Returns: a jstring representing the security context of the pid,
   *          the jstring may be NULL if there was an error
   * Exceptions: none
   */
  static jstring getPidCon(JNIEnv *env, jobject clazz, jint pid) {
#ifdef HAVE_SELINUX
    security_context_t context = NULL;
    jstring securityString = NULL;

    pid_t checkPid = (pid_t)pid;

    if(getpidcon(checkPid, &context) == -1) {
      LOGE("getPidCon: Error retrieving context of pid '%d' (%s)", checkPid, strerror(errno));
      goto bail;
    }

    LOGV("getPidCon: Successfully retrived context '%s' for pid '%d'", context, checkPid);

    securityString = env->NewStringUTF(context);

  bail:
    if(context != NULL)
      freecon(context);

    return securityString;
#else
    return NULL;
#endif
  }

  static jboolean checkSELinuxAccess(JNIEnv *env, jobject clazz, jstring scon, jstring tcon, jstring tclass, jstring perm) {
#ifdef HAVE_SELINUX
    char *myscon = const_cast<char *> (env->GetStringUTFChars(scon, NULL));
    char *mytcon = const_cast<char *> (env->GetStringUTFChars(tcon, NULL));
    const char *mytclass = env->GetStringUTFChars(tclass, NULL);
    const char *myperm = env->GetStringUTFChars(perm, NULL);
    return (selinux_check_access(myscon, mytcon, mytclass, myperm, NULL) == 0) ? true : false;
#else
    return true;
#endif
  }

  /*
   * JNI registration.
   */
  static JNINativeMethod method_table[] = {

    /* name,                     signature,                    funcPtr */
    { "checkSELinuxAccess"       , "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z" , (void*)checkSELinuxAccess },
    { "getContext"               , "()Ljava/lang/String;"                         , (void*)getCon           },
    { "getFileContext"           , "(Ljava/lang/String;)Ljava/lang/String;"       , (void*)getFileCon       },
    { "getPeerContext"           , "(Ljava/io/FileDescriptor;)Ljava/lang/String;" , (void*)getPeerCon       },
    { "getPidContext"            , "(I)Ljava/lang/String;"                        , (void*)getPidCon        },
    { "isSELinuxEnforced"        , "()Z"                                          , (void*)isSELinuxEnforced},
    { "isSELinuxEnabled"         , "()Z"                                          , (void*)isSELinuxEnabled },
    { "setFileContext"           , "(Ljava/lang/String;Ljava/lang/String;)Z"      , (void*)setFileCon       },
    { "setFSCreateContext"       , "(Ljava/lang/String;)Z"                        , (void*)setFSCreateCon   },
  };

  static int log_callback(int type, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    LOG_PRI_VA(ANDROID_LOG_ERROR, "SELinux", fmt, ap);
    va_end(ap);
    return 0;
  }

  int register_android_os_SELinux(JNIEnv *env) {
#ifdef HAVE_SELINUX
    union selinux_callback cb;
    cb.func_log = log_callback;
    selinux_set_callback(SELINUX_CB_LOG, cb);
#endif
    return AndroidRuntime::registerNativeMethods(
         env, "android/os/SELinux",
         method_table, NELEM(method_table));
  }
}
