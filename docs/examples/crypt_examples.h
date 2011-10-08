#define EX_STEP(step_nr, format, args...)	do { \
							printf("STEP_%02d: Entering "format"... ", step_nr, ##args); \
						} while(0)

#define EX_FAIL(format, args...)	do { \
						printf("FAIL\n"); \
						fprintf(stderr, "\t"format"\n", ##args); \
					} while(0)

#define EX_SUCCESS(format, args...)	do { \
						printf("OK\n\t"format"\n", ##args); \
					} while(0)

#define EX_DELIM	printf("-------------------------------\n")

#define EX_PRESS_ENTER(msg, args...)	do { \
						printf(msg "\nPress <ENTER> to continue: ", ##args); \
						getc(stdin); \
					} while(0)

