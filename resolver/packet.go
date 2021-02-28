package resolver

import (
	//"bytes"
	"encoding/binary"
	"fmt"
)

// BytePacketBuffer holds the DNS packet contents, along with a position
type BytePacketBuffer struct {
	buffer [512]byte
	pos    int
}

// Step the current position of the buffer up by size
func (b *BytePacketBuffer) Step(size int) {
	b.pos += size
}

// Read the byte at the current position and advance the position by one
func (b *BytePacketBuffer) Read() (byte, error) {
	v, err := b.Get()
	b.pos += 1
	return v, err
}

// ReadN bytes of the buffer and advance the position N times
func (b *BytePacketBuffer) ReadN(n int) ([]byte, error) {
	v, err := b.GetN(n)
	b.pos += n
	return v, err
}

// Get the byte at the current position
func (b *BytePacketBuffer) Get() (byte, error) {
	if b.pos >= 512 {
		return byte(0), fmt.Errorf("get: end of buffer reached")
	}
	return b.buffer[b.pos], nil
}

// Get the bytes from b.pos to b.pos + n
func (b *BytePacketBuffer) GetN(n int) ([]byte, error) {
	if b.pos+n >= 512 {
		return []byte{}, fmt.Errorf("readn: end of buffer reached")
	}
	v := b.buffer[b.pos : b.pos+n]
	return v, nil
}

// decodeName is a recursive function that assumes
const maxRecursionLevel = 5
func (b *BytePacketBuffer) decodeName(offset int, buffer *[]byte, level int) ([]byte, int, error) {
	if level > maxRecursionLevel {
		return nil, 0, fmt.Errorf("readqueryname: max recursion level exceeded")
	}
	start := len(*buffer)
	index := offset

	// We've hit a label of zero length, indicating the end of a name
	if b.buffer[index] == 0x00 {
		return nil, index + 1, nil
	}
loop:
	for b.buffer[index] != 0x00 {
		switch b.buffer[index] & 0xc0 {
		default:
			/* RFC 1035
			   A domain name represented as a sequence of labels, where
			   each label consists of a length octet followed by that
			   number of octets.  The domain name terminates with the
			   zero length octet for the null label of the root.  Note
			   that this field may be an odd number of octets; no
			   padding is used.
			*/
			index2 := index + int(b.buffer[index]) + 1
			if index2-offset > 255 {
				return nil, 0, fmt.Errorf("readqueryname: Name too long")
			} else if index2 < index+1 || index2 > len(b.buffer) {
				return nil, 0, fmt.Errorf("readqueryname: Invalid index")
			}
			*buffer = append(*buffer, '.')
			*buffer = append(*buffer, b.buffer[index+1:index2]...)
			index = index2

		case 0xc0:
			/* RFC 1035
			   The pointer takes the form of a two octet sequence.
			   The first two bits are ones.  This allows a pointer to
			   be distinguished from a label, since the label must
			   begin with two zero bits because labels are restricted
			   to 63 octets or less.  (The 10 and 01 combinations are
			   reserved for future use.)  The OFFSET field specifies
			   an offset from the start of the message (i.e., the
			   first octet of the ID field in the domain header).  A
			   zero offset specifies the first byte of the ID field,
			   etc.
			   The compression scheme allows a domain name in a message to be
			   represented as either:
			      - a sequence of labels ending in a zero octet
			      - a pointer
			      - a sequence of labels ending with a pointer
			*/
			if index+2 > len(b.buffer) {
				return nil, 0, fmt.Errorf("readqueryname: Offset too high")
			}
			offsetp := int(binary.BigEndian.Uint16(b.buffer[index:index+2]) & 0x3fff)
			if offsetp > len(b.buffer) {
				return nil, 0, fmt.Errorf("readqueryname: Offset too high")
			}
			// This looks a little tricky, but actually isn't.  Because of how
			// decodeName is written, calling it appends the decoded name to the
			// current buffer.  We already have the start of the buffer, then, so
			// once this call is done buffer[start:] will contain our full name.
			_, _, err := b.decodeName(offsetp, buffer, level+1)
			if err != nil {
				return nil, 0, err
			}
			index++ // pointer is two bytes, so add an extra byte here.
			break loop
		/* EDNS, or other DNS option ? */
		case 0x40: // RFC 2673
			return nil, 0, fmt.Errorf("qname '0x40' - RFC 2673 unsupported yet (data=%x index=%d)",
				b.buffer[index], index)

		case 0x80:
			return nil, 0, fmt.Errorf("qname '0x80' unsupported yet (data=%x index=%d)",
				b.buffer[index], index)
		}
		if index >= len(b.buffer) {
			return nil, 0,  fmt.Errorf("readqueryname: Invalid index")
		}
	}
	if len(*buffer) <= start {
		return (*buffer)[start:], index + 1, nil
	}
	return (*buffer)[start+1:], index + 1, nil
}
