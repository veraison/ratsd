package config

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"golang.org/x/text/cases"
)

var ErrNilConfig = errors.New("nil configuration")

type IValidatable interface {
	Validate() error
}

type Loader struct {
	config    *mapstructure.DecoderConfig
	exclusive bool
}

func NewLoader(dest interface{}) *Loader {
	loader := &Loader{exclusive: true}
	if err := loader.Init(dest); err != nil {
		panic(err)
	}
	return loader
}

func NewNonExclusiveLoader(dest interface{}) *Loader {
	loader := &Loader{exclusive: false}
	if err := loader.Init(dest); err != nil {
		panic(err)
	}
	return loader
}

func (loader *Loader) Init(dest interface{}) error {
	if dest == nil {
		return errors.New("cannot initialize loader with nil dest")
	}

	value := reflect.ValueOf(dest)
	if value.Kind() != reflect.Pointer || reflect.Indirect(value).Kind() != reflect.Struct {
		return fmt.Errorf("expected pointer to a struct but got %v", value.Kind())
	}

	loader.config = &mapstructure.DecoderConfig{
		ErrorUnused:      loader.exclusive,
		ErrorUnset:       true,
		WeaklyTypedInput: true,
		Metadata:         &mapstructure.Metadata{},
		Result:           dest,
	}
	return nil
}

func (loader Loader) LoadFromMap(source map[string]interface{}) error {
	decoder, err := mapstructure.NewDecoder(loader.config)
	if err != nil {
		return err
	}

	input, err := loader.mapFromStruct(loader.config.Result)
	if err != nil {
		return err
	}
	for key, value := range source {
		input[key] = value
	}

	if err = decoder.Decode(input); err != nil {
		decodeErr, ok := err.(*mapstructure.Error)
		if !ok {
			return err
		}

		var messages []string
		for _, subError := range decodeErr.Errors {
			parts := strings.Split(subError, "has invalid keys: ")
			if len(parts) > 1 {
				messages = append(messages, fmt.Sprintf("unexpected directives: %s", parts[1]))
				continue
			}
			parts = strings.Split(subError, "has unset fields: ")
			if len(parts) > 1 {
				messages = append(messages, fmt.Sprintf("directives not found: %s", parts[1]))
				continue
			}
			messages = append(messages, subError)
		}
		return errors.New(strings.Join(messages, "; "))
	}

	if ok, err := govalidator.ValidateStruct(loader.config.Result); !ok {
		return err
	}
	if validatable, ok := loader.config.Result.(IValidatable); ok {
		return validatable.Validate()
	}
	return nil
}

func (loader Loader) LoadFromViper(source *viper.Viper) error {
	if source == nil {
		return ErrNilConfig
	}
	return loader.LoadFromMap(source.AllSettings())
}

func (loader Loader) mapFromStruct(source interface{}) (map[string]interface{}, error) {
	value := reflect.Indirect(reflect.ValueOf(source))
	typeInfo := value.Type()
	if value.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct but got %s", typeInfo.Name())
	}

	result := map[string]interface{}{}
	caser := cases.Fold()
	for index := 0; index < typeInfo.NumField(); index++ {
		field := typeInfo.Field(index)
		fieldValue := value.Field(index)
		if fieldValue.IsZero() {
			allowZero := false
			for _, part := range strings.Split(field.Tag.Get("config"), ",") {
				if part == "zerodefault" {
					allowZero = true
					break
				}
			}
			if !allowZero {
				continue
			}
		}

		tag := field.Tag.Get(loader.config.TagName)
		if comma := strings.Index(tag, ","); comma != -1 {
			tag = tag[:comma]
		}
		fieldName := tag
		if fieldName == "" {
			fieldName = caser.String(field.Name)
		}
		result[fieldName] = fieldValue.Interface()
	}
	return result, nil
}
