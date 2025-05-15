package opf

const (
	MockBankBrand   string = "MockBank"
	MockBankCNPJ    string = "58540569000120"
	DefaultCurrency string = "BRL"
)

type ContextKey string

const (
	CtxKeyClientID      ContextKey = "client_id"
	CtxKeySubject       ContextKey = "subject"
	CtxKeyScopes        ContextKey = "scopes"
	CtxKeyConsentID     ContextKey = "consent_id"
	CtxKeyInteractionID ContextKey = "interaction_id"
	CtxKeyOrgID         ContextKey = "org_id"
)
