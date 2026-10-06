fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            let _ = libmkiso_fuzz::udf::roundtrip(data);
        });
    }
}
