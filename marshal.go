package dns

// UnmarshalJSON(data []byte) (err error)
func (rr *A) MarshalJSON() ([]byte, error) {
//	b, _ := json.Marshal(rr.Header())
b := []byte(`"` + rr.A.String() + `"`)
	return b, nil
}

