package geneve

const (
	// TODO: register our own option class with IANA.
	OptionTypeKeyEpoch  = OptionTypeCritical | 0x01
	OptionTypeTxCounter = OptionTypeCritical | 0x02
)
