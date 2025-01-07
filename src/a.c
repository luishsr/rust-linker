// We'll reference 'my_add' externally and call it.
extern int my_add(int x, int y);

int foo(int val) {
    // We'll just call my_add with 'val' and 5
    return my_add(val, 5);
}
