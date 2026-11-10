package audit

import (
	"unsafe"
	mem "unsafe"

	"golang.org/x/sys/windows"
)

func audit(data []byte, pointer *byte, raw unsafe.Pointer, text string, address uintptr) {
	// ok: use-of-unsafe-block
	_ = unsafe.Sizeof(windows.SecurityAttributes{})
	// ruleid: use-of-unsafe-block
	_ = unsafe.Pointer(pointer)
	// ruleid: use-of-unsafe-block
	_ = unsafe.Pointer(address)
	// ruleid: use-of-unsafe-block
	_ = unsafe.Add(raw, 1)
	// ruleid: use-of-unsafe-block
	_ = unsafe.Slice(pointer, 1)
	// ruleid: use-of-unsafe-block
	_ = unsafe.SliceData(data)
	// ruleid: use-of-unsafe-block
	_ = unsafe.String(pointer, 1)
	// ruleid: use-of-unsafe-block
	_ = unsafe.StringData(text)
	// ruleid: use-of-unsafe-block
	_ = unsafe.Sizeof(pointer)
	// ruleid: use-of-unsafe-block
	_ = unsafe.Alignof(windows.SecurityAttributes{})
	// ruleid: use-of-unsafe-block
	_ = unsafe.Offsetof(windows.SecurityAttributes{}.Length)
	// ruleid: use-of-unsafe-block
	_ = unsafe.Sizeof(windows.SecurityAttributes{Length: 1})
	// ruleid: use-of-unsafe-block
	_ = unsafe.Pointer(uintptr(unsafe.Sizeof(windows.SecurityAttributes{})))
	// ruleid: use-of-unsafe-block
	_ = unsafe.Sizeof(windows.SecurityAttributes{SecurityDescriptor: (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(pointer))})
	// ruleid: use-of-unsafe-block
	_ = mem.Pointer(pointer)
	// ruleid: use-of-unsafe-block
	_ = mem.Add(raw, 1)
}
