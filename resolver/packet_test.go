package resolver

import (
	"fmt"
	"strings"
	"testing"
)

func TestBytePacketBuffer_Step(t *testing.T) {
	var buffer [512]byte
	// Fill up a buffer from 0 - 255 twice
	for i := 0; i < 512; i++ {
		buffer[i] = byte(i)
	}
	b := BytePacketBuffer{
		buffer: buffer,
		pos:    0,
	}

	// Can we step forward?
	b.Step(3)
	if b.pos != 3 {
		t.Errorf("b.Step(3) = %d; want 3", b.pos)
	}

	// Can we step backwards?
	b.pos = 3
	b.Step(-1)
	if b.pos != 2 {
		t.Errorf("b.Step(-1) = %d; want 2", b.pos)
	}
}

func TestBytePacketBuffer_decodeName(t *testing.T) {
	// This represents www.google.com
	var buffer = [512]byte{03, 119, 119, 119, 46, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109}
	// Fill up a buffer from 0 - 63 twice
	b := BytePacketBuffer{
		buffer: buffer,
		pos:    0,
	}
	var buff []byte
	v, _, err := b.decodeName(0, &buff, 0)
	if err != nil {
		t.Error(err)
	}
	if strings.Compare(string(v),"www.google.com") == 0 {
		fmt.Println(string(v) == "www.google.com")
		t.Fail()
	}
	/*
		b := BytePacketBuffer {
			buffer: buffer,
			pos: 0,
		}
	*/
}
