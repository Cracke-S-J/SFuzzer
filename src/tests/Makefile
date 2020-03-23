wrapper:
	g++ -c ../utils/log.cpp -I ../utils/ -o log.o
	g++ -c ../wrapper/wrapper.cpp -I ../utils/ -I ../wrapper/include -o wrapper.o
	g++ -c testwrapper.cpp -I ../wrapper/include -I ../utils/ -o testwrapper.o
	g++ testwrapper.o wrapper.o log.o -o testwrapper
clean:
	rm log.o wrapper.o testwrapper.o testwrapper
