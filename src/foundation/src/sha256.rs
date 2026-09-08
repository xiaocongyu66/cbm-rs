//! sha256.rs — 1:1 rewrite of `src/foundation/sha256.{c,h}`.
//!
//! SHA-256 per FIPS 180-4, straightforward reference implementation,
//! plus streaming context, hex helper, and HMAC-SHA256. Validated against
//! the NIST test vectors (same vectors as the C tests/test_cli.c).

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub const DIGEST_LEN: usize = 32;
pub const HEX_LEN: usize = 64;
const BLOCK: usize = 64;

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    bitlen: u64,
    buf: [u8; BLOCK],
    buflen: usize,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            bitlen: 0,
            buf: [0; BLOCK],
            buflen: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.buf[self.buflen] = b;
            self.buflen += 1;
            if self.buflen == BLOCK {
                let block = self.buf;
                self.transform(&block);
                self.bitlen += 512;
                self.buflen = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        self.bitlen += self.buflen as u64 * 8;
        let mut i = self.buflen;
        self.buf[i] = 0x80;
        i += 1;
        if i > 56 {
            while i < BLOCK {
                self.buf[i] = 0;
                i += 1;
            }
            let block = self.buf;
            self.transform(&block);
            i = 0;
        }
        while i < 56 {
            self.buf[i] = 0;
            i += 1;
        }
        for (j, slot) in self.buf[56..64].iter_mut().enumerate() {
            *slot = (self.bitlen >> (56 - 8 * j)) as u8;
        }
        let block = self.buf;
        self.transform(&block);

        let mut out = [0u8; DIGEST_LEN];
        for (j, s) in self.state.iter().enumerate() {
            out[j * 4..j * 4 + 4].copy_from_slice(&s.to_be_bytes());
        }
        out
    }

    fn transform(&mut self, data: &[u8; BLOCK]) {
        let mut m = [0u32; 64];
        #[allow(clippy::needless_range_loop)]
        for i in 0..16 {
            let j = i * 4;
            m[i] = u32::from_be_bytes([data[j], data[j + 1], data[j + 2], data[j + 3]]);
        }
        for i in 16..64 {
            m[i] = sig1(m[i - 2])
                .wrapping_add(m[i - 7])
                .wrapping_add(sig0(m[i - 15]))
                .wrapping_add(m[i - 16]);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let t1 = h
                .wrapping_add(ep1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(m[i]);
            let t2 = ep0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}
fn ep0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}
fn ep1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}
fn sig0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}
fn sig1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

/// One-shot digest as lowercase hex (64 chars).
pub fn sha256_hex(data: &[u8]) -> String {
    let mut c = Sha256::new();
    c.update(data);
    let digest = c.finalize();
    let mut out = String::with_capacity(HEX_LEN);
    for b in digest {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
    }
    out
}

/// HMAC-SHA256 per RFC 2104 (block = 64 bytes).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut normalized_key = [0u8; BLOCK];
    let k: &[u8] = if key.len() > BLOCK {
        let mut c = Sha256::new();
        c.update(key);
        let d = c.finalize();
        normalized_key[..DIGEST_LEN].copy_from_slice(&d);
        &normalized_key
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
        &normalized_key
    };

    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        inner_pad[i] ^= k[i];
        outer_pad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(&inner_pad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&outer_pad);
    outer.update(&inner_digest);
    outer.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn million_a_vector() {
        // 'a' * 1_000_000
        let mut c = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            c.update(&chunk);
        }
        assert_eq!(
            hex(&c.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn streaming_equals_oneshot() {
        let data: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        let mut c = Sha256::new();
        for chunk in data.chunks(7) {
            c.update(chunk);
        }
        assert_eq!(hex(&c.finalize()), sha256_hex(&data));
    }

    #[test]
    fn rfc4231_hmac_vectors() {
        // RFC 4231 test case 2
        let out = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex(&out),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Test case 6: key larger than block (131 bytes of 0xaa)
        let key = [0xaau8; 131];
        let out = hmac_sha256(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hex(&out),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }
}
