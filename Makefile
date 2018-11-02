CC = g++
CFLAGS = -Wall -Wextra -pedantic -static-libstdc++
LOGIN = xkapou04
FILES = Makefile feedreader.cpp protokol.pdf readme
FEEDREADERFILES = feedreader.cpp
LDFLAGS = -L/usr/local/ssl/lib
LDLIBS = -lssl -lcrypto

DOC_FOLDER = doc
DOC_NAME = manual

TEST_FOLDER = test

all: feedreader
	
feedreader: $(FEEDREADERFILES)
	$(CC) $(CFLAGS) -o $@ $(FEEDREADERFILES) $(LDFLAGS) $(LDLIBS)

doc: $(DOC_FOLDER)/$(DOC_NAME).tex $(DOC_FOLDER)/literatura.bib
	cd $(DOC_FOLDER) && latex $(DOC_NAME).tex
	cd $(DOC_FOLDER) && bibtex $(DOC_NAME).aux
	cd $(DOC_FOLDER) && latex $(DOC_NAME).tex
	cd $(DOC_FOLDER) && latex $(DOC_NAME).tex
	cd $(DOC_FOLDER) && dvips -t a4 $(DOC_NAME).dvi
	cd $(DOC_FOLDER) && ps2pdf $(DOC_NAME).ps
	mv $(DOC_FOLDER)/$(DOC_NAME).pdf $(DOC_NAME).pdf

clean:
	rm -f *.o *.out feedreader *.tar.gz *~
	rm -f ./$(DOC_FOLDER)/*.aux
	rm -f ./$(DOC_FOLDER)/*.dvi
	rm -f ./$(DOC_FOLDER)/*.ps
	rm -f ./$(DOC_FOLDER)/*.bbl
	rm -f ./$(DOC_FOLDER)/*.bbg
	rm -f ./$(DOC_FOLDER)/*.log
	rm -f ./$(DOC_FOLDER)/*.toc
	rm -f ./$(DOC_FOLDER)/*.blg
	rm -f ./$(DOC_FOLDER)/*.pdf
	rm -f ./$(DOC_FOLDER)/*.out
	rm -f ./$(TEST_FOLDER)/*.out

test: feedreader FORCE
	echo "Test:"
	mkdir -p $(TEST_FOLDER)
	dos2unix runtest
	./runtest

FORCE: ;
