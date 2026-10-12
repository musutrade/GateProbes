#![allow(dead_code, unused_parens, unused_must_use)]
struct Pair { a: i32, b: i32 }
fn id(x: i32) -> i32 { x }
fn fallible(x: i32) -> Result<i32, ()> { Ok(x) }
fn main() {
 let tuple = |x| Ok::<_, ()>((fallible(x)?, x));
 let negate = |x: i32| !x.is_positive();
 let arithmetic = |x: i32| -(x + 1);
 let array = |x| [id(x), x];
 let structure = |x| Pair { a: id(x), b: x };
 let paren = |x| (((id(x))));
 let cast = |x: i32| x as i64;
 let call = |x| id(x);
 let nested = |x| Ok::<_, ()>(Some((fallible(x)?, x)));
 let block = |x| { id(x) };
 let binary = |x| id(x) + id(x);
 let condition = |x| if x { 1 } else { 2 };
 let short = |x| x && std::hint::black_box(false);
 let uncalled = |x: i32| !x.is_positive();
 let outer = |x| { let inner = |y| if y { 1 } else { 2 }; inner(x) };
 let future = || async { if std::hint::black_box(true) { 1 } else { 2 } };
 let v = std::hint::black_box(1);
 std::hint::black_box(tuple(v)); std::hint::black_box(negate(v));
 std::hint::black_box(arithmetic(v)); std::hint::black_box(array(v));
 std::hint::black_box(structure(v)); std::hint::black_box(paren(v));
 std::hint::black_box(cast(v));
 std::hint::black_box(call(v)); std::hint::black_box(nested(v));
 std::hint::black_box(block(v)); std::hint::black_box(binary(v));
 std::hint::black_box(condition(true)); std::hint::black_box(short(true));
 std::hint::black_box(outer(true)); std::mem::drop(future());
 if std::hint::black_box(false) { std::hint::black_box(uncalled(v)); }
}
