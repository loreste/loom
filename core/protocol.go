package core

// ProtocolVersion is the compatibility contract for adapter and SDK payloads.
// Additive response fields are allowed within a major version; changing the
// meaning of a field or a denial reason requires a new version.
const ProtocolVersion = "1"

// ProtocolHeader is the HTTP header adapters use to advertise the contract.
const ProtocolHeader = "X-Loom-Protocol-Version"
