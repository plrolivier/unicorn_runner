int main()
{
    volatile int a = 1;
    volatile int b = 2;
    volatile int c;

    c = a + b;

    return c;
}