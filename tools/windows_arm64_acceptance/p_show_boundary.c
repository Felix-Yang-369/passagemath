#include <gc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "standard.h"
#include "poly.h"

static int check(const char *label, Term *term, long count, const char *expected)
{
    Poly poly;
    char *actual;
    poly.term = term;
    poly.len = count;
    actual = p_show(&poly);
    if (strcmp(actual, expected)) {
        fprintf(stderr, "%s: expected <%s>, got <%s>\n", label, expected, actual);
        return 1;
    }
    printf("PSHOW_OK %s <%s>\n", label, actual);
    return 0;
}

int main(void)
{
    Term one = {1, 0, 0}, minusone = {-1, 0, 0};
    Term coefficient = {123456789, 0, 0};
    Term exponent = {1, 32767, -32767};
    Term mixed[] = {{-1, 0, -4}, {-2, 0, -2}, {1, 2, -2}};
    Term signs[] = {{1, 0, 0}, {2, 0, 0}, {-3, 0, 0}};
    Term *many;
    Poly poly;
    char *text;
    int i, failed = 0;
    if (_get_printf_count_output() != 0) return 90;
    GC_INIT();
    failed += check("zero", NULL, 0, "0");
    failed += check("one", &one, 1, "1");
    failed += check("minusone", &minusone, 1, " - 1");
    failed += check("coefficient", &coefficient, 1, "123456789");
    failed += check("exponents", &exponent, 1, "M^32767L^-32767");
    failed += check("trefoil", mixed, 3, " - L^-4 - 2L^-2 + M^2L^-2");
    failed += check("signs", signs, 3, "1 + 2 - 3");
    many = GC_MALLOC(10000 * sizeof(Term));
    for (i=0; i<10000; i++) {
        many[i].coef=2;
        many[i].m=0;
        many[i].l=0;
    }
    poly.term=many;
    poly.len=10000;
    text=p_show(&poly);
    if (strlen(text)!=39997 || text[0]!='2') failed++;
    for (i=1; i<10000; i++) {
        if (memcmp(text+1+(i-1)*4," + 2",4)) failed++;
    }
    if (_get_printf_count_output()!=0) return 91;
    printf("PSHOW_GROWTH_OK length=%zu failures=%d\n",strlen(text),failed);
    return failed ? 1 : 0;
}
