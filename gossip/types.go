package gossip

// STHVersion reflects the STH Version field in RFC6862[-bis]
type STHVersion int

// STHVersion constants
const (
	STHVersion0 = 0
	STHVersion1 = 1
)

// SCTFeedbackEntry represents a single piece of SCT feedback.
type SCTFeedbackEntry struct {
	X509Chain []string `json:"x509_chain"`
	SCTData   []string `json:"sct_data"`
}

// SCTFeedback represents a collection of SCTFeedback which a client might send together.
type SCTFeedback struct {
	Feedback []SCTFeedbackEntry `json:"sct_feedback"`
}

// STHPollinationEntry is a pollination record for a single STH
type STHPollinationEntry struct {
	STHVersion           STHVersion `json:"sth_version"`
	TreeSize             int64      `json:"tree_size"`
	Timestamp            int64      `json:"timestamp"`
	Sha256RootHashB64    string     `json:"sha256_root_hash"`
	TreeHeadSignatureB64 string     `json:"tree_head_signature"`
	LogID                string     `json:"log_id"`
}

// STHPollination represents a collection of STH pollination entries which a client might send together.
type STHPollination struct {
	STHs []STHPollinationEntry `json:"sths"`
}
