// Package textclean strips control characters from text that came from a
// scanned host before it can reach a terminal. Host output (key comments,
// paths, error messages) is chosen by whoever controls the host, and an
// escape sequence in it would be run by the terminal of whoever reads the
// report.
package textclean

import (
	"reflect"
	"strings"
	"unicode"
)

// String replaces control characters, ESC and the C1 set included, with
// "?". Tabs and newlines stay: they carry no commands.
func String(s string) string {
	if !needs(s) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r != '\n' && r != '\t' && unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

func needs(s string) bool {
	for _, r := range s {
		if r != '\n' && r != '\t' && unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// Strings cleans, in place, every string reachable from v (a pointer):
// struct fields, slices, arrays, map keys and values, through pointers and
// interfaces. Unexported fields are left alone.
func Strings(v any) {
	walk(reflect.ValueOf(v))
}

func walk(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			walk(v.Elem())
		}
	case reflect.String:
		if v.CanSet() {
			if s := v.String(); needs(s) {
				v.SetString(String(s))
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				walk(v.Field(i))
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			walk(v.Index(i))
		}
	case reflect.Map:
		if v.IsNil() {
			return
		}
		iter := v.MapRange()
		type kv struct{ k, v reflect.Value }
		var changed []kv
		for iter.Next() {
			k, val := iter.Key(), iter.Value()
			// Map values cannot be set in place: copy, clean, put back.
			nv := reflect.New(val.Type()).Elem()
			nv.Set(val)
			walk(nv)
			nk := k
			if k.Kind() == reflect.String && needs(k.String()) {
				nk = reflect.ValueOf(String(k.String())).Convert(k.Type())
			}
			changed = append(changed, kv{nk, nv})
			if nk.Interface() != k.Interface() {
				v.SetMapIndex(k, reflect.Value{}) // the old key goes
			}
		}
		for _, c := range changed {
			v.SetMapIndex(c.k, c.v)
		}
	}
}
