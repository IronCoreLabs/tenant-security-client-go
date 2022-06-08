package tsc

type SecurityEvent = string

const (
	AdminAddEvent               SecurityEvent = "ADMIN_ADD"
	AdminRemoveEvent            SecurityEvent = "ADMIN_REMOVE"
	AdminChangePermissionsEvent SecurityEvent = "ADMIN_CHANGE_PERMISSIONS"
	AdminChangeSSettingEvent    SecurityEvent = "ADMIN_CHANGE_SETTING"
)

const (
	DataImportEvent            SecurityEvent = "DATA_IMPORT"
	DataExportEvent            SecurityEvent = "DATA_EXPORT"
	DataEncryptEvent           SecurityEvent = "DATA_ENCRYPT"
	DataDecryptEvent           SecurityEvent = "DATA_DECRYPT"
	DataCreateEvent            SecurityEvent = "DATA_CREATE"
	DataDeleteEvent            SecurityEvent = "DATA_DELETE"
	DataDenyAccessEvent        SecurityEvent = "DATA_DENY_ACCESS"
	DataChangePermissionsEvent SecurityEvent = "DATA_CHANGE_PERMISSIONS"
)

const (
	PeriodicEnforceRetentionPolicyEvent SecurityEvent = "ENFORCE_RETENTION_POLICY"
	PeriodicCreateBackupEvent           SecurityEvent = "CREATE_BACKUP"
)

const (
	UserAddEvent               SecurityEvent = "USER_ADD"
	UserSuspendEvent           SecurityEvent = "USER_SUSPEND"
	UserRemoveEvent            SecurityEvent = "USER_REMOVE"
	UserLoginEvent             SecurityEvent = "USER_LOGIN"
	UserTimeoutSessionEvent    SecurityEvent = "USER_TIMEOUT_SESSION"
	UserLockoutEvent           SecurityEvent = "USER_LOCKOUT"
	UserLogoutEvent            SecurityEvent = "USER_LOGOUT"
	UserChangePermissionsEvent SecurityEvent = "USER_CHANGE_PERMISSIONS"
	UserExpirePasswordEvent    SecurityEvent = "USER_EXPIRE_PASSWORD"
	//nolint: gosec
	UserResetPasswordEvent            SecurityEvent = "USER_RESET_PASSWORD"
	UserChangePasswordEvent           SecurityEvent = "USER_CHANGE_PASSWORD"
	UserRejectLoginEvent              SecurityEvent = "USER_REJECT_LOGIN"
	UserEnableTwoFactorEvent          SecurityEvent = "USER_ENABLE_TWO_FACTOR"
	UserDisableTwoFactorEvent         SecurityEvent = "USER_DISABLE_TWO_FACTOR"
	UserChangeEmailEvent              SecurityEvent = "USER_CHANGE_EMAIL"
	UserRequestEmailVerificationEvent SecurityEvent = "USER_REQUEST_EMAIL_VERIFICATION"
	UserVerifyEmailEvent              SecurityEvent = "USER_VERIFY_EMAIL"
)
