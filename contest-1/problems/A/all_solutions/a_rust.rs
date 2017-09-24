use std::io;
use std::io::Read;
fn main()
{
    let mut instr = String::new();
    io::stdin().read_to_string(&mut instr).expect("err");
    let mut viter = instr.split_whitespace();
    let a = viter.next().unwrap().parse::<i32>().expect("err");
    let b = viter.next().unwrap().parse::<i32>().expect("err");
    let c = a + b;
    println!("{}", c);
}
