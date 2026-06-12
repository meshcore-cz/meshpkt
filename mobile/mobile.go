// Package mobile exposes the stable meshpkt API to gomobile.
//
// Keep this package intentionally tiny. Complex Go types stay inside the root
// meshpkt package and do not cross the Java/Kotlin boundary.
package mobile

import "github.com/meshcore-cz/meshpkt"

// Call invokes a registered meshpkt operation.
//
// argsJSON is a JSON array containing positional arguments. The returned string
// is always a JSON object containing either the operation result fields or an
// "error" field.
func Call(name, argsJSON string) string {
	return meshpkt.CallJSON(name, argsJSON)
}
