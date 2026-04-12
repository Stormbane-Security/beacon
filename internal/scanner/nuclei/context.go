package nuclei

import "context"

type contextKey string

const nucleiTagsKey contextKey = "nuclei_tags"

// WithTags returns a context carrying nuclei template tags derived from
// fingerprinting. The nuclei scanner reads these to run only relevant
// templates instead of the full 7,000+ template set.
func WithTags(ctx context.Context, tags []string) context.Context {
	return context.WithValue(ctx, nucleiTagsKey, tags)
}

// TagsFromContext retrieves the fingerprint-derived nuclei tags.
// Returns nil if no tags were set (run all templates).
func TagsFromContext(ctx context.Context) []string {
	tags, _ := ctx.Value(nucleiTagsKey).([]string)
	return tags
}
