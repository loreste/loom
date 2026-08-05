package core

// DefaultOperationVersion is used for operations registered before explicit
// versioning was added.
const DefaultOperationVersion = "1"

func NormalizeOperationVersion(version string) string {
	if version == "" {
		return DefaultOperationVersion
	}
	return version
}
