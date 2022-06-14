package main

import "C"

import (
	"fmt"
	"io/ioutil"
	"os"
	"unsafe"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

//export verifyGo
func verifyGo(
	layoutPathc *C.char,
	pubKeyPathsc **C.char,
	pubKeyCountc C.int,
	intermediatePathsc **C.char,
	intermediatePathCountc C.int,
	linkDirc *C.char,
	lineNormalizationc C.int) *C.char {
	var layoutMb intoto.Metablock

	layoutPath := C.GoString(layoutPathc)
	if err := layoutMb.Load(layoutPath); err != nil {
		e := fmt.Errorf("failed to load layout at %s: %w", layoutPath, err)
		return C.CString("Error:: " + e.Error())
	}

	pubKeyCount := int(pubKeyCountc)
	layoutKeys := make(map[string]intoto.Key, pubKeyCount)

	pubKeyPaths := (*[1 << 30]*C.char)(unsafe.Pointer(pubKeyPathsc))[:pubKeyCount:pubKeyCount]
	for _, pubKeyPathc := range pubKeyPaths {
		var pubKey intoto.Key
		pubKeyPath := C.GoString(pubKeyPathc)
		if err := pubKey.LoadKeyDefaults(pubKeyPath); err != nil {
			e := fmt.Errorf("invalid key at %s: %w", pubKeyPath, err)
			return C.CString("Error:: " + e.Error())
		}

		layoutKeys[pubKey.KeyID] = pubKey
	}

	intermediatePathCount := int(intermediatePathCountc)
	intermediatePems := make([][]byte, 0, int(intermediatePathCount))
	intermediatePaths := (*[1 << 30]*C.char)(unsafe.Pointer(intermediatePathsc))[:intermediatePathCount:intermediatePathCount]

	for _, intermediatec := range intermediatePaths {
		intermediate := C.GoString(intermediatec)
		f, err := os.Open(intermediate)
		if err != nil {
			e := fmt.Errorf("failed to open intermediate %s: %w", intermediate, err)
			return C.CString("Error:: " + e.Error())
		}
		defer f.Close()

		pemBytes, err := ioutil.ReadAll(f)
		if err != nil {
			e := fmt.Errorf("failed to read intermediate %s: %w", intermediate, err)
			return C.CString("Error:: " + e.Error())
		}

		intermediatePems = append(intermediatePems, pemBytes)

		if err := f.Close(); err != nil {
			e := fmt.Errorf("could not close intermediate cert: %w", err)
			return C.CString("Error:: " + e.Error())
		}
	}

	var lineNormalization bool
	lineNormalizationInt := int(lineNormalizationc)
	if lineNormalizationInt == 0 {
		lineNormalization = false
	} else {
		lineNormalization = true
	}

	linkDir := C.GoString(linkDirc)
	_, err := intoto.InTotoVerify(layoutMb, layoutKeys, linkDir, "", make(map[string]string), intermediatePems, lineNormalization)
	if err != nil {
		e := fmt.Errorf("inspection failed: %w", err)
		return C.CString("Error:: " + e.Error())
	}

	return C.CString("")
}

func main() {}
