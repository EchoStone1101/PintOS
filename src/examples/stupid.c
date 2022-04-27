int
main (void)
{
  int *p;

  /* Should PF at 0x0804b300. */
  p = (int*) 0x0804b300;
  *p = 0xDEADBEEF;
  p = (int*) 0x08048000;
  *p = 0xDEADBEEF;
  
  return 0;

  /* not reached */
}
