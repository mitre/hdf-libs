package audit

import (
	"syscall"
	"unsafe"
	mem "unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/windows"
)

func audit(ace *windows.ACCESS_ALLOWED_ACE, fn uintptr, data []byte, pointer *byte, raw unsafe.Pointer, text string, address uintptr, out uintptr) {
	// unsafe.Sizeof is a compile-time constant; its operand is never evaluated.
	// ok: use-of-unsafe-block
	_ = unsafe.Sizeof(windows.SecurityAttributes{})
	// ok: use-of-unsafe-block
	_ = unsafe.Sizeof(pointer)

	// A pointer converted in the argument list of purego.SyscallN is kept alive and
	// unmoved for the call (unsafe.Pointer rule 4, go:uintptrescapes).
	// ok: use-of-unsafe-block
	purego.SyscallN(fn, uintptr(unsafe.Pointer(pointer)))
	// ok: use-of-unsafe-block
	purego.SyscallN(fn, uintptr(3), uintptr(unsafe.Pointer(&out)), 0)

	// Stored before the call, the uintptr no longer keeps the object alive.
	// ruleid: use-of-unsafe-block
	stored := uintptr(unsafe.Pointer(pointer))
	purego.SyscallN(fn, stored)
	// Rule 4 is honoured here too, but only purego.SyscallN is allowed.
	// ruleid: use-of-unsafe-block
	_, _, _ = syscall.Syscall(fn, uintptr(unsafe.Pointer(pointer)), 0, 0)
	// An unsafe operation nested inside an allowed argument is still reported.
	// ruleid: use-of-unsafe-block
	purego.SyscallN(fn, uintptr(unsafe.Pointer(unsafe.Add(raw, 1))))
	// ruleid: use-of-unsafe-block
	purego.SyscallN(fn, uintptr(unsafe.Pointer(unsafe.StringData(text))))
	// Each argument stands alone: an allowed one does not excuse its neighbours.
	// ok: use-of-unsafe-block
	purego.SyscallN(fn, uintptr(unsafe.Pointer(pointer)), uintptr(unsafe.Pointer(&out)))
	// ruleid: use-of-unsafe-block
	purego.SyscallN(fn, uintptr(unsafe.Pointer(pointer)), uintptr(unsafe.Add(raw, 1)))
	// ruleid: use-of-unsafe-block
	purego.SyscallN(fn, uintptr(unsafe.Pointer(pointer)), uintptr(unsafe.Pointer(pointer))+1)
	// ruleid: use-of-unsafe-block
	purego.SyscallN(fn, uintptr(unsafe.Pointer(pointer)), uintptr(unsafe.Slice(pointer, 1)[0]))
	// The function address is not an argument the call keeps alive.
	// ruleid: use-of-unsafe-block
	purego.SyscallN(uintptr(unsafe.Pointer(pointer)), 0)
	// ruleid: use-of-unsafe-block
	purego.SyscallN(fn, uintptr(unsafe.Pointer(unsafe.Pointer(pointer))))

	// An ACE's SID is variable-length and starts at SidStart (ACCESS_ALLOWED_ACE layout).
	// ok: use-of-unsafe-block
	_ = (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	// ruleid: use-of-unsafe-block
	_ = (*byte)(unsafe.Pointer(&ace.SidStart))
	// ruleid: use-of-unsafe-block
	_ = (*windows.SID)(unsafe.Pointer(&ace.Mask))
	// ruleid: use-of-unsafe-block
	_ = unsafe.Pointer(&ace.SidStart)
	// ruleid: use-of-unsafe-block
	_ = (*windows.SID)(unsafe.Pointer(&(*windows.ACCESS_ALLOWED_ACE)(unsafe.Pointer(pointer)).SidStart))

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
	_ = unsafe.Alignof(windows.SecurityAttributes{})
	// ruleid: use-of-unsafe-block
	_ = unsafe.Offsetof(windows.SecurityAttributes{}.Length)
	// ruleid: use-of-unsafe-block
	_ = unsafe.Pointer(uintptr(unsafe.Sizeof(windows.SecurityAttributes{})))
	// ruleid: use-of-unsafe-block
	_ = unsafe.Sizeof(windows.SecurityAttributes{SecurityDescriptor: (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(pointer))})
	// ruleid: use-of-unsafe-block
	_ = mem.Pointer(pointer)
	// ruleid: use-of-unsafe-block
	_ = mem.Add(raw, 1)
}
