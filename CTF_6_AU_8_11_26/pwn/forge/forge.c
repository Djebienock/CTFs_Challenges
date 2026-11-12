// forge - House of Force (glibc 2.27, Ubuntu 18.04)
// gcc -O0 -std=gnu11 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now -o forge forge.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_NOTES 16

struct note {
    char  *data;
    size_t size;
};

static struct note notes[MAX_NOTES];

static void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(60);
}

// reads up to n bytes, stops at '\n' (not stored), does not terminate the string
static size_t read_until_nl(char *buf, size_t n) {
    size_t i = 0;
    char c;
    while (i < n) {
        if (read(0, &c, 1) != 1)
            _exit(0);
        if (c == '\n')
            break;
        buf[i++] = c;
    }
    return i;
}

static unsigned long read_ulong(void) {
    char line[32] = {0};
    unsigned long v = 0;
    read_until_nl(line, sizeof(line) - 1);
    for (char *p = line; *p >= '0' && *p <= '9'; p++)
        v = v * 10 + (*p - '0');
    return v;
}

static unsigned long read_index(void) {
    printf("index> ");
    unsigned long i = read_ulong();
    if (i >= MAX_NOTES || !notes[i].data) {
        puts("no such note.");
        return MAX_NOTES;
    }
    return i;
}

static void forge(void) {
    int i;
    for (i = 0; i < MAX_NOTES && notes[i].data; i++)
        ;
    if (i == MAX_NOTES) {
        puts("the forge is full.");
        return;
    }
    printf("size> ");
    size_t size = read_ulong();
    char *p = malloc(size);           // any size, the smith does not judge
    if (!p) {
        puts("the metal cracked.");
        return;
    }
    notes[i].data = p;
    notes[i].size = size;
    printf("content> ");
    read_until_nl(p, size);
    printf("forged #%d\n", i);
}

static void temper(void) {
    unsigned long i = read_index();
    if (i == MAX_NOTES)
        return;
    char *p = notes[i].data;
    printf("more content> ");
    read_until_nl(p + strlen(p), notes[i].size);   // BUG: should be size - strlen(p)
    puts("tempered.");
}

static void inspect(void) {
    unsigned long i = read_index();
    if (i == MAX_NOTES)
        return;
    printf("#%lu: ", i);
    puts(notes[i].data);
}

static void melt(void) {
    unsigned long i = read_index();
    if (i == MAX_NOTES)
        return;
    free(notes[i].data);
    notes[i].data = NULL;
    notes[i].size = 0;
    puts("melted.");
}

int main(void) {
    setup();
    puts("=== THE FORGE ===");
    for (;;) {
        puts("\n1. forge\n2. temper\n3. inspect\n4. melt\n5. leave");
        printf("> ");
        switch (read_ulong()) {
        case 1: forge();   break;
        case 2: temper();  break;
        case 3: inspect(); break;
        case 4: melt();    break;
        case 5: puts("the fire dies down."); return 0;
        default: puts("?");
        }
    }
}
