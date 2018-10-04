cc = gcc
prom = syn
src = syn_flood.c

$(prom): $(src)
	$(cc) -o $(prom) $(src) -O2 -std=c99