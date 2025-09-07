package payment

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type PIX struct {
	Key           string
	Amount        string
	TransactionID string
}

var amountRx = regexp.MustCompile(`^\d{1,10}\.\d{2}$`)

// ParsePIX parses a Pix "copia e cola" (BR Code / EMV MPM) and extracts key/amount/txid.
// https://www.bcb.gov.br/content/estabilidadefinanceira/spb_docs/ManualBRCode.pdf.
func ParsePIX(copyPaste string) (PIX, error) {
	s := strings.TrimSpace(copyPaste)
	if len(s) < 8 {
		return PIX{}, fmt.Errorf("invalid PIX code: too short")
	}

	root, err := tlvDecode(s)
	if err != nil {
		return PIX{}, err
	}

	var out PIX

	// Tag 54 - Amount.
	out.Amount = tlvFirstValue(root, "54")
	if out.Amount != "" && !amountRx.MatchString(out.Amount) {
		return PIX{}, errors.New("invalid amount: use format 123.45")
	}

	// TxID (62/05) – optional; "***" means absent.
	if ad := tlvFirst(root, "62"); ad != nil {
		subs, _ := tlvDecode(ad.Value)
		if tx := tlvSubValue(subs, "05"); tx != "" && tx != "***" {
			out.TransactionID = tx
		}
	}

	// Merchant Account Information (26..51). Look for GUI "br.gov.bcb.pix".
	for _, t := range root {
		idn, _ := strconv.Atoi(t.ID)
		if idn < 26 || idn > 51 {
			continue
		}
		subs, _ := tlvDecode(t.Value)
		gui := strings.ToLower(tlvSubValue(subs, "00"))
		if gui != "br.gov.bcb.pix" {
			continue
		}
		// Static: chave under subtag 01. Dynamic: URL under subtag 25 (we ignore URL here).
		if key := tlvSubValue(subs, "01"); key != "" {
			out.Key = key
		}
		break
	}

	return out, nil
}

// tlv is a TLV (Tag-Length-Value) pair.
type tlv struct{ ID, Value string }

func tlvDecode(s string) ([]tlv, error) {
	var out []tlv
	for i := 0; i < len(s); {
		if i+4 > len(s) {
			return nil, errors.New("truncated TLV header")
		}
		id := s[i : i+2]
		ln, err := strconv.Atoi(s[i+2 : i+4])
		if err != nil || ln < 1 {
			return nil, fmt.Errorf("bad length for ID %s", id)
		}
		i += 4
		if i+ln > len(s) {
			return nil, fmt.Errorf("truncated value for ID %s", id)
		}
		out = append(out, tlv{ID: id, Value: s[i : i+ln]})
		i += ln
	}
	return out, nil
}

func tlvFirst(tlvs []tlv, id string) *tlv {
	for i := range tlvs {
		if tlvs[i].ID == id {
			return &tlvs[i]
		}
	}
	return nil
}

func tlvFirstValue(tlvs []tlv, id string) string {
	if t := tlvFirst(tlvs, id); t != nil {
		return t.Value
	}
	return ""
}

func tlvSubValue(subs []tlv, id string) string {
	for _, s := range subs {
		if s.ID == id {
			return s.Value
		}
	}
	return ""
}
