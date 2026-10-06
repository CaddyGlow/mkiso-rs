fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            libmkiso_fuzz::iso9660(data);
            libmkiso_fuzz::udf(data);
        });
    }
}
