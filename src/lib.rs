#![feature(convert)]
extern crate bytebuffer;
use bytebuffer::{ByteBuffer, BO, Buffer, Putter, AsVec};

#[test]
fn it_works() {
  md5_init();
  assert_eq!(md5(""), "d41d8cd98f00b204e9800998ecf8427e");
  assert_eq!(md5("a"), "0cc175b9c0f1b6a831c399e269772661");
  assert_eq!(md5("abc"), "900150983cd24fb0d6963f7d28e17f72");
  assert_eq!(md5("message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
  assert_eq!(md5("abcdefghijklmnopqrstuvwxyz"),
             "c3fcd3d76192e4007dfb496cca67e13b");
  assert_eq!(md5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
             "d174ab98d277d9f5a5611c2c9f419d9f"); 
  assert_eq!(md5("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
             "57edf4a22be3c955ac49da2e2107b67a");
}

static INIT_A: u32 = 0x67452301;
static INIT_B: u32 = 0xefcdab89;
static INIT_C: u32 = 0x98badcfe;
static INIT_D: u32 = 0x10325476;

static T_SIZE: usize = 64;

static SHIFT_AMTS: [u32; 16] 
  = [ 7, 12, 17, 22,
      5,  9, 14, 20,
      4, 11, 16, 23,
      6, 10, 15, 21 ];

static mut TABLE_T: [u32; 64] = [0u32; 64];

pub fn md5_init() {
  unsafe {
    for i in 0..TABLE_T.len() {
      TABLE_T[i] = (((1u64 << 32) as f64) 
                      * ((i + 1) as f64).sin().abs()) as u32;
    }
  }
}

fn md5_compute(message: &[u8]) -> Vec<u8> {
  let mut padded = ByteBuffer::allocate((((message.len() + 8) / 64) + 1) * 64);
  let cap = padded.cap();
  padded.set_order(BO::LittleEndian)
        .put_bytes(message).unwrap()
        .put(0x80 as u8)
        .set_pos(cap - 8).unwrap()
        .put_u64((message.len() * 8) as u64).unwrap()
        .rewind();
  let (mut a, mut b, mut c, mut d) = (INIT_A, INIT_B, INIT_C, INIT_D);

  while padded.has_remaining() {
    let chunk 
      = match padded.slice()
                    .set_order(BO::LittleEndian)
                    .as_u32_vec() {
                      None => panic!("Can't convert a bytebuffer to a u32 vector!!"),
                      Some(vec) => vec,                 
                    };  
    let (origi_a, origi_b, origi_c, origi_d) = (a, b, c, d);

    for i in 0..64 {
      let mut div16 = i >> 4;
      let mut f: u32 = 0;
      let mut buffer_index = i;

      match div16 {
        0 => f = (b & c) | (!b & d),
        1 => {
          f = (b & d) | (c & !d); 
          buffer_index = (buffer_index * 5 + 1) & 0x0F;
        },
        2 => {
          f = b ^ c ^ d;
          buffer_index = (buffer_index * 3 + 5) & 0x0F;
        },
        3 => {
          f = c ^ (b | !d);
          buffer_index = (buffer_index * 7) & 0x0F;
        },
        _ => panic!("Something terrible is happening!"),
      };
    
      let tmp = unsafe {
        b.wrapping_add( a.wrapping_add(f)
                         .wrapping_add(match chunk.get(buffer_index) {
                                         None => 
                                           panic!("buffer index is out of the range!!"),
                                         Some(res) => *res,
                                       })
                         .wrapping_add(TABLE_T[i])
                         .rotate_left(SHIFT_AMTS[(div16 << 2) | (i & 3)]) ) 
      };

      a = d;
      d = c;
      c = b;
      b = tmp;  
    }

    a = a.wrapping_add(origi_a);
    b = b.wrapping_add(origi_b);
    c = c.wrapping_add(origi_c);
    d = d.wrapping_add(origi_d);
    let pos = padded.get_pos() + 64;
    let last = cap - 1;
    padded.set_pos( if pos < last { pos } else { last } );
  }

  let mut result = ByteBuffer::allocate(16);
  result.set_order(BO::LittleEndian);
  for n in vec![a, b, c, d] {
    result.put_u32(n);
  }
  result.vector().unwrap()
}  

fn to_hex_string(src: &Vec<u8>) -> String {
  let dst: Vec<_> = src.iter()
                       .map(|&x| format!("{:02x}", x & 0xFF) )
                       .collect();
  dst.as_slice().concat()
}

pub fn md5(src: &str) -> String {
  let dst_vec = md5_compute(src.as_bytes());
  println!("{:?}", dst_vec);
  to_hex_string(&dst_vec)
}
