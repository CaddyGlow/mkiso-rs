fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            libmkiso_fuzz::roundtrip(data);
        });
    }
}
