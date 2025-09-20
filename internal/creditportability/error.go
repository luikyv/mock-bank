package creditportability

import (
	"github.com/luikyv/mock-bank/internal/errorutil"
)

var (
	ErrNotFound                                   = errorutil.New("portability not found")
	ErrClientNotAllowed                           = errorutil.New("access is not allowed to client")
	ErrPortabilityInProgress                      = errorutil.New("portability is in progress")
	ErrContractNotEligible                        = errorutil.New("contract is not eligible for portability")
	ErrIncompatibleInformation                    = errorutil.New("incompatible information")
	ErrIncompatibleInstalmentPeriodicity          = errorutil.New("instalment periodicity is not the same as the contract instalment periodicity")
	ErrInstalmentTermOverLimit                    = errorutil.New("instalment term is over limit")
	ErrProposedAmountOverLimit                    = errorutil.New("proposed amount is over limit")
	ErrPortabilityNotAcceptedSettlementInProgress = errorutil.New("portability is not in accepted settlement in progress status")
	ErrCancelNotAllowed                           = errorutil.New("portability cannot be cancelled")
)
