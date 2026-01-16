use obfuse::obfuse;

fn main() {
    println!("{}", obfuse!("hello world").as_str());
}
