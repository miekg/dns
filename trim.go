package dns

import "strings"

// trim trims origin from s if s is a subdomain of origin. If this is done Trim
// will return a relative name. If s is not a subdomain it will be returned
// as-is.
//
// It will return "@" if s equals origin. Both arguments need to be fully qualified.
// It assumes s and origin have the same encoding and quoting for things like \DDD constructs.
func trim(s, origin string) string {
	if s == origin {
		return "@"
	}
	if origin == "." {
		return s[:len(s)-1]
	}

	start := strings.TrimSuffix(s, "."+origin)
	if start == "" {
		return "@"
	}

	return start
}
