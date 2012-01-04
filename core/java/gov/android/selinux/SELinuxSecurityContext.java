package gov.android.selinux;

/**                                                                                                                                                                                                                                       
 * Class to hold an SELinux user:role:type[:level] security context.
 * This class will take a security_context_t style string and convert it to
 * a SELinuxSecurity class. This class can also produce a security_context_t
 * style string from a SELinuxContext class.
*/
public class SELinuxSecurityContext {

    /**
     * Nonvariable logcat tag
     */
    private static final String TAG = "SELinuxSecurityContext";

    /**
     * String representing the user security context identity 
     */
    private String mUser;

    /**
     * String representing the role security context identity 
     */
    private String mRole;

    /**
     * String representing the type security context identity 
     */
    private String mType;

    /**
     * String representing the level security context identity. 
     * Since this field is optional, any missing, or empty, level field
     * in a context string will be set to NULL internally
     */
    private String mLevel;

    /**
     * Nonvariable delimiter used to parse an SELinux security_context_t style string
     */
    private static final String SECURITY_CONTEXT_DELIMITER = ":";

    /**
     * Creates a Security Context class from an SELinux security_context_t 
     * style string
     * @param securityContext a string of the form user:role:type[:level]
     * @exception IllegalArgumentException if securityContext parameter is null, empty
     *            or violates the security label syntax
     */
    public SELinuxSecurityContext(String securityContext) throws IllegalArgumentException {

	String user;
	String role;
	String type;
	String level;
	
	if(securityContext == null || securityContext.equals("")) {
	    throw new IllegalArgumentException("Incorrect security context string. Null or empty string");
	}

	String[] contextPieces = securityContext.split(SECURITY_CONTEXT_DELIMITER, 4);
	int numOfPieces = contextPieces.length;

	// there should be three pieces with an optional fourth
	if(numOfPieces != 3 && numOfPieces != 4) {
	    throw new IllegalArgumentException("Incorrect security context string : " + securityContext);
	}

	user = contextPieces[0];
	role = contextPieces[1];
	type = contextPieces[2];

	// optional MCS/MLS piece
	level = numOfPieces == 4 ? contextPieces[3]  : null;

	if(! isValidSecurityContext(user, role, type, level)) {
            throw new IllegalArgumentException("Incorrect security context string : " + securityContext);
	}

	mUser = user;
        mRole = role;
        mType = type;
        mLevel = level;
    }


    /**                                                                                                                                                                                                                                   
     * Creates an SELinux security context class with empty level field
     * @param user a string representing SELinux user identity 
     * @param role a string representing SELinux role
     * @param type a string representing SElinux 
     */
    public SELinuxSecurityContext(String user, String role, String type) throws IllegalArgumentException {
	this(user, role, type, null);
    }


    /**
     * Creates an SELinux security context class given all fields
     * @param user a string representing SELinux user identity
     * @param role a string representing SELinux role
     * @param type a string representing SElinux
     * @param level a string representing SELinux 
     */
    public SELinuxSecurityContext(String user, String role, String type, String level) throws IllegalArgumentException {

	if(! isValidSecurityContext(user, role, type, level)) {
	    throw new IllegalArgumentException("Incorrect security context arguments");
	}

	mUser = user;
	mRole = role;
	mType = type;
	mLevel = level;
    }


    /**
     * Returns the user identity of the security context of the current 
     * SELinuxSEcurityContext class
     * @return String representing the user identity
     */
    public String getUserContext() {

	return mUser;
    }

    /**
     * Returns the security context role of the current SELinuxSEcurityContext class
     * @return String representing the context role
     */
    public String getRoleContext() {

	return mRole;
    }

    /**
     * Returns the security context type of the current SELinuxSEcurityContext class
     * @return String representing the security context type
     */
    public String getTypeContext() {

	return mType;
    }

    /**
     * Returns the security context level of the current SELinuxSEcurityContext class
     * @return String representing the security context level,
     *    possible values are null or a valid level string
     */
    public String getLevelContext() {

	return mLevel;
    }


    /**
     * Does general type checking and field presence checking
     * of the current Security Context class fields. Makes sure
     * we conform to user:role:type[:level]
     * @param user
     * @param role
     * @param type
     * @param level
     * @return true if conforms, false otherwise
     * @hide
     */
    private boolean isValidSecurityContext(String user, String role, String type, String level) {
	
	if(user == null || user.equals(""))
	    return false;
	if(role == null || role.equals(""))
	    return false;
	if(type == null || type.equals(""))
	    return false;
	if(level != null && level.equals(""))
	    return false;

	return true;
    }

    
    /**
     * Converts an SELinuxSecurityContext class to an SELinux
     * security_context_t style string. No syntax checking is required
     * on the returned string for valid fields.
     * @params
     * @return security context style string of the form user:role:type[:level] 
     */
    public String toString() {

	String user = getUserContext();
	String role = getRoleContext();
	String type = getTypeContext();
	String level = getLevelContext();

	StringBuilder securityContext = new StringBuilder();
	securityContext.append(user + ":");
	securityContext.append(role + ":");
	securityContext.append(type);
	securityContext.append(level != null ? ":" + level : "");

	return securityContext.toString();
    }



}
