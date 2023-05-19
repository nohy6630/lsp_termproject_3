CC = gcc

MONITOR = ssu_monitor

$(MONITOR) : $(MONITOR).o
	$(CC) -w -o $(MONITOR) $(MONITOR).o

$(MONITOR).o : $(MONITOR).h
	$(CC) -w -c -o $@ $(MONITOR).c

clean :
	rm -rf $(MONITOR)
	rm -rf *.o
