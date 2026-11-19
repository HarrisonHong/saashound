package okta

// The wire structs below are the subsets of Okta JSON the provider decodes.
// They deliberately omit secret-bearing fields (a created app's client_secret,
// a TOTP shared secret): a field the struct does not name is dropped by the
// JSON decoder, so a credential in a response can never reach a journal or a
// result record.

type apiUser struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Profile struct {
		Login     string `json:"login"`
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"profile"`
}

type apiFactor struct {
	ID         string `json:"id"`
	FactorType string `json:"factorType"`
	Status     string `json:"status"`
	Profile    struct {
		CredentialID string `json:"credentialId"`
	} `json:"profile"`
}

type apiRole struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

type apiZone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type apiIdp struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type apiApp struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Status string `json:"status"`
	// Only the non-secret client_id is read back; client_secret is omitted on
	// purpose and never stored.
	Credentials struct {
		OAuthClient struct {
			ClientID string `json:"client_id"`
		} `json:"oauthClient"`
	} `json:"credentials"`
}

type apiGrant struct {
	ID      string `json:"id"`
	ScopeID string `json:"scopeId"`
	Status  string `json:"status"`
}

type apiPolicy struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type apiRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Actions struct {
		AppSignOn struct {
			VerificationMethod struct {
				FactorMode string `json:"factorMode"`
			} `json:"verificationMethod"`
		} `json:"appSignOn"`
	} `json:"actions"`
}

// requiresFactor reports whether the rule still enforces MFA.
func (r apiRule) requiresFactor() bool {
	return r.Actions.AppSignOn.VerificationMethod.FactorMode != "1FA"
}

type apiGroup struct {
	ID      string `json:"id"`
	Profile struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"profile"`
}

type apiOrg struct {
	ID          string `json:"id"`
	Subdomain   string `json:"subdomain"`
	CompanyName string `json:"companyName"`
	Status      string `json:"status"`
}

type apiCustomRole struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type apiResourceSet struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type apiBinding struct {
	ID   string `json:"id"`
	Role string `json:"role"`
}
