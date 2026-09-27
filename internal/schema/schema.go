// Package schema generates JSON Schema (draft 2020-12) documents from the Go
// result types and validates JSON against them. docs/schema/*.v1.json are
// generated, and a test fails if they drift from the code.
package schema

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Doc is a JSON Schema node.
type Doc = map[string]any

// Generate returns the schema for t, titled id.
func Generate(id, title string, t reflect.Type) Doc {
	d := node(t)
	d["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	d["$id"] = "https://github.com/jlugo32/hostops/docs/schema/" + id + ".json"
	d["title"] = title
	if props, ok := d["properties"].(Doc); ok {
		if s, ok := props["schema"].(Doc); ok {
			s["const"] = "hostops." + id
		}
	}
	return d
}

func node(t reflect.Type) Doc {
	for t.Kind() == reflect.Pointer {
		return Doc{"anyOf": []any{node(t.Elem()), Doc{"type": "null"}}}
	}
	switch t.Kind() {
	case reflect.String:
		return Doc{"type": "string"}
	case reflect.Bool:
		return Doc{"type": "boolean"}
	case reflect.Int, reflect.Int64, reflect.Int32:
		return Doc{"type": "integer"}
	case reflect.Float64, reflect.Float32:
		return Doc{"type": "number"}
	case reflect.Slice:
		return Doc{"type": "array", "items": node(t.Elem())}
	case reflect.Map:
		return Doc{"type": "object", "additionalProperties": node(t.Elem())}
	case reflect.Struct:
		props := Doc{}
		var req []string
		collect(t, props, &req)
		sort.Strings(req)
		return Doc{"type": "object", "properties": props, "required": req, "additionalProperties": false}
	}
	panic(fmt.Sprintf("schema: unsupported kind %s", t.Kind()))
}

func collect(t reflect.Type, props Doc, req *[]string) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if f.Anonymous && tag == "" {
			collect(f.Type, props, req)
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		props[name] = node(f.Type)
		if !strings.Contains(opts, "omitempty") {
			*req = append(*req, name)
		}
	}
}

// Validate checks v (decoded JSON) against d. It supports the subset
// Generate emits: type, properties, required, additionalProperties, items,
// anyOf and const.
func Validate(d Doc, v any, path string) error {
	if c, ok := d["const"]; ok && c != v {
		return fmt.Errorf("%s: want const %v, got %v", path, c, v)
	}
	if any, ok := d["anyOf"].([]any); ok {
		for _, alt := range any {
			if Validate(alt.(Doc), v, path) == nil {
				return nil
			}
		}
		return fmt.Errorf("%s: matches no alternative", path)
	}
	switch d["type"] {
	case "null":
		if v != nil {
			return fmt.Errorf("%s: want null", path)
		}
	case "string":
		if _, ok := v.(string); !ok {
			return fmt.Errorf("%s: want string, got %T", path, v)
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("%s: want boolean, got %T", path, v)
		}
	case "integer":
		f, ok := v.(float64)
		if !ok || f != float64(int64(f)) {
			return fmt.Errorf("%s: want integer, got %v", path, v)
		}
	case "number":
		if _, ok := v.(float64); !ok {
			return fmt.Errorf("%s: want number, got %T", path, v)
		}
	case "array":
		a, ok := v.([]any)
		if !ok {
			return fmt.Errorf("%s: want array, got %T", path, v)
		}
		for i, x := range a {
			if err := Validate(d["items"].(Doc), x, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case "object":
		o, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: want object, got %T", path, v)
		}
		props, _ := d["properties"].(Doc)
		if props != nil {
			for _, r := range d["required"].([]string) {
				if _, ok := o[r]; !ok {
					return fmt.Errorf("%s: missing required %q", path, r)
				}
			}
			for k, x := range o {
				p, ok := props[k]
				if !ok {
					return fmt.Errorf("%s: unexpected property %q", path, k)
				}
				if err := Validate(p.(Doc), x, path+"."+k); err != nil {
					return err
				}
			}
		} else if ap, ok := d["additionalProperties"].(Doc); ok {
			for k, x := range o {
				if err := Validate(ap, x, path+"."+k); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
