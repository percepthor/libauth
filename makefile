TYPE		:= development

NATIVE		:= 0

COVERAGE	:= 0

SANITIZER	:=

SLIB		:= libauth.so

all: directories $(SLIB)

directories:
	@mkdir -p $(TARGETDIR)
	@mkdir -p $(BUILDDIR)

install: $(SLIB)
	install -m 644 ./bin/libauth.so /usr/local/lib/
	cp -R ./include/auth /usr/local/include

uninstall:
	rm /usr/local/lib/libauth.so
	rm -r /usr/local/include/auth

PTHREAD 	:= -l pthread
MATH		:= -lm

OPENSSL		:= -l ssl -l crypto

CURL		:= -l curl

CERVER		:= -l cerver
CERVER_INC	:= -I /usr/local/include/cerver

DEFINES		:= -D _GNU_SOURCE

DEVELOPMENT	:= -D PERCEPTHOR_DEBUG

# the test build lowers the timeouts of a request to the auth service,
# so the cases of a slow auth service do not take half a minute each,
# and the largest answer, so the stub can answer one that does not fit
TESTLIMITS	:= -D AUTH_REQUEST_CONNECT_TIMEOUT=2 -D AUTH_REQUEST_TIMEOUT=2 -D AUTH_RESPONSE_MAX_SIZE=4096

# only the AUTH_EXPORT and AUTH_PUBLIC functions are exported by the library
VISIBILITY	:= -fvisibility=hidden

CC          := gcc

GCCVGTEQ8 	:= $(shell expr `gcc -dumpversion | cut -f1 -d.` \>= 8)

SRCDIR      := src
INCDIR      := include

BUILDDIR    := objs
TARGETDIR   := bin

SRCEXT      := c
DEPEXT      := d
OBJEXT      := o

COVDIR		:= coverage
COVEXT		:= gcov

# common flags
# -Wconversion
COMMON		:= -Wall -Wno-unknown-pragmas \
				-Wfloat-equal -Wdouble-promotion -Wint-to-pointer-cast -Wwrite-strings \
				-Wtype-limits -Wsign-compare -Wmissing-field-initializers \
				-Wuninitialized -Wmaybe-uninitialized -Wempty-body \
				-Wunused-parameter -Wunused-but-set-parameter -Wunused-result \
				-Wformat -Wformat-nonliteral -Wformat-security -Wformat-overflow -Wformat-signedness -Wformat-truncation

# main
CFLAGS      := $(DEFINES)

ifeq ($(TYPE), development)
	CFLAGS += -g -fasynchronous-unwind-tables $(DEVELOPMENT)
else ifeq ($(TYPE), test)
	CFLAGS += -g -fasynchronous-unwind-tables -D_FORTIFY_SOURCE=2 -fstack-protector -O2 $(TESTLIMITS)
	ifeq ($(COVERAGE), 1)
		CFLAGS += -fprofile-arcs -ftest-coverage
	endif
else ifeq ($(TYPE), beta)
	CFLAGS += -g -D_FORTIFY_SOURCE=2 -O2
else
	CFLAGS += -D_FORTIFY_SOURCE=2 -O2
endif

# check which compiler we are using
ifeq ($(CC), g++)
	CFLAGS += -std=c++11 -fpermissive
else
	CFLAGS += -std=c11 -Wpedantic -pedantic-errors
	# check for compiler version
	ifeq "$(GCCVGTEQ8)" "1"
    	CFLAGS += -Wcast-function-type
	else
		CFLAGS += -Wbad-function-cast
	endif
endif

ifeq ($(NATIVE), 1)
	CFLAGS += -march=native
endif

# address,undefined or thread, for the library and for the tests
ifneq ($(SANITIZER),)
	SANITIZERFLAGS := -fsanitize=$(SANITIZER) -fno-omit-frame-pointer
endif

# common flags
CFLAGS += -fPIC $(VISIBILITY) $(COMMON) $(SANITIZERFLAGS)

LIB         := -L /usr/local/lib $(PTHREAD) $(MATH) $(OPENSSL) $(CURL) $(CERVER) $(SANITIZERFLAGS)

ifeq ($(TYPE), test)
	ifeq ($(COVERAGE), 1)
		LIB += -lgcov --coverage
	endif
endif

INC         := -I $(INCDIR) -I /usr/local/include $(CERVER_INC)
INCDEP      := -I $(INCDIR)

SOURCES     := $(shell find $(SRCDIR) -type f -name *.$(SRCEXT))
OBJECTS     := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.$(OBJEXT)))

SRCCOVS		:= $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.$(SRCEXT).$(COVEXT)))

# pull in dependency info for *existing* .o files
-include $(OBJECTS:.$(OBJEXT)=.$(DEPEXT))

$(SLIB): $(OBJECTS)
	$(CC) $^ $(LIB) -shared -o $(TARGETDIR)/$(SLIB)

# compile sources
$(BUILDDIR)/%.$(OBJEXT): $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC) $(LIB) -c -o $@ $<
	@$(CC) $(CFLAGS) $(INCDEP) -MM $(SRCDIR)/$*.$(SRCEXT) > $(BUILDDIR)/$*.$(DEPEXT)
	@cp -f $(BUILDDIR)/$*.$(DEPEXT) $(BUILDDIR)/$*.$(DEPEXT).tmp
	@sed -e 's|.*:|$(BUILDDIR)/$*.$(OBJEXT):|' < $(BUILDDIR)/$*.$(DEPEXT).tmp > $(BUILDDIR)/$*.$(DEPEXT)
	@sed -e 's/.*://' -e 's/\\$$//' < $(BUILDDIR)/$*.$(DEPEXT).tmp | fmt -1 | sed -e 's/^ *//' -e 's/$$/:/' >> $(BUILDDIR)/$*.$(DEPEXT)
	@rm -f $(BUILDDIR)/$*.$(DEPEXT).tmp

# tests: every file of test/unit/ is a binary, test/integration/ is one binary
TESTDIR		:= test
TESTBUILD	:= $(TESTDIR)/objs
TESTTARGET	:= $(TESTDIR)/bin
TESTCOVDIR	:= $(COVDIR)/test

TESTFLAGS	:= -g $(DEFINES) $(TESTLIMITS) -Wall -Wno-unknown-pragmas -Wno-format $(SANITIZERFLAGS)

ifeq ($(TYPE), test)
	ifeq ($(COVERAGE), 1)
		TESTFLAGS += -fprofile-arcs -ftest-coverage
	endif
endif

ifeq ($(NATIVE), 1)
	TESTFLAGS += -march=native
endif

# the tests link the objects of the library, so they also reach its AUTH_PRIVATE functions,
# that libauth.so does not export
TESTLIBS	:= $(OBJECTS) -L /usr/local/lib $(PTHREAD) $(CURL) $(CERVER) $(SANITIZERFLAGS)

ifeq ($(TYPE), test)
	ifeq ($(COVERAGE), 1)
		TESTLIBS += -lgcov --coverage
	endif
endif

TESTINC		:= -I $(INCDIR) -I ./$(TESTDIR) $(CERVER_INC)

UNITS		:= $(shell find $(TESTDIR)/unit -type f -name *.$(SRCEXT) 2> /dev/null)
INTEGRATION	:= $(shell find $(TESTDIR)/integration -type f -name *.$(SRCEXT) 2> /dev/null)

UNITOBJS	:= $(patsubst $(TESTDIR)/%,$(TESTBUILD)/%,$(UNITS:.$(SRCEXT)=.$(OBJEXT)))
INTEGRATIONOBJS	:= $(patsubst $(TESTDIR)/%,$(TESTBUILD)/%,$(INTEGRATION:.$(SRCEXT)=.$(OBJEXT)))

TESTOBJS	:= $(UNITOBJS) $(INTEGRATIONOBJS)

TESTCOVS	:= $(patsubst $(TESTDIR)/%,$(TESTBUILD)/%,$(UNITS:.$(SRCEXT)=.$(SRCEXT).$(COVEXT)))

units: testout $(OBJECTS) $(UNITOBJS)
	$(foreach unit,$(UNITOBJS),$(CC) $(TESTINC) $(unit) -o ./$(TESTTARGET)/$(basename $(notdir $(unit))) $(TESTLIBS) || exit 1;)

integration: testout $(OBJECTS) $(INTEGRATIONOBJS)
	$(CC) $(TESTINC) $(INTEGRATIONOBJS) -o ./$(TESTTARGET)/integration $(TESTLIBS)

testout:
	@mkdir -p ./$(TESTTARGET)

test: testout
	$(MAKE) $(TESTOBJS)
	$(MAKE) units
	$(MAKE) integration

# compile tests
$(TESTBUILD)/%.$(OBJEXT): $(TESTDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	$(CC) $(TESTFLAGS) $(TESTINC) -c -o $@ $<
	@$(CC) $(TESTFLAGS) $(TESTINC) -MM $(TESTDIR)/$*.$(SRCEXT) > $(TESTBUILD)/$*.$(DEPEXT)
	@cp -f $(TESTBUILD)/$*.$(DEPEXT) $(TESTBUILD)/$*.$(DEPEXT).tmp
	@sed -e 's|.*:|$(TESTBUILD)/$*.$(OBJEXT):|' < $(TESTBUILD)/$*.$(DEPEXT).tmp > $(TESTBUILD)/$*.$(DEPEXT)
	@sed -e 's/.*://' -e 's/\\$$//' < $(TESTBUILD)/$*.$(DEPEXT).tmp | fmt -1 | sed -e 's/^ *//' -e 's/$$/:/' >> $(TESTBUILD)/$*.$(DEPEXT)
	@rm -f $(TESTBUILD)/$*.$(DEPEXT).tmp

# fuzzing with libFuzzer: make TYPE=test CC=clang fuzz
FUZZDIR			:= $(TESTDIR)/fuzz
FUZZBUILD		:= $(BUILDDIR)/fuzz
FUZZTARGET		:= $(TESTTARGET)/fuzz

FUZZSANITIZERS	:= address,undefined
FUZZLIBFLAGS	:= -g -O1 $(DEFINES) -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,$(FUZZSANITIZERS)
FUZZFLAGS		:= -g -O1 $(DEFINES) -fno-omit-frame-pointer -fsanitize=fuzzer,$(FUZZSANITIZERS)
FUZZLIBS		:= -L /usr/local/lib $(PTHREAD) $(MATH) $(OPENSSL) $(CURL) $(CERVER)
FUZZINC			:= -I $(INCDIR) -I ./$(TESTDIR) $(CERVER_INC)

FUZZERS			:= $(shell find $(FUZZDIR) -maxdepth 1 -type f -name *.$(SRCEXT) 2> /dev/null)
FUZZLIBOBJS		:= $(patsubst $(SRCDIR)/%,$(FUZZBUILD)/%,$(SOURCES:.$(SRCEXT)=.$(OBJEXT)))

fuzz: $(FUZZLIBOBJS)
	@mkdir -p ./$(FUZZTARGET)
	$(foreach fuzzer,$(FUZZERS),$(CC) $(FUZZFLAGS) $(FUZZINC) $(fuzzer) $(FUZZLIBOBJS) -o ./$(FUZZTARGET)/$(basename $(notdir $(fuzzer))) $(FUZZLIBS) || exit 1;)

$(FUZZBUILD)/%.$(OBJEXT): $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(dir $@)
	$(CC) $(FUZZLIBFLAGS) $(INC) -c -o $@ $<

# coverage of the library from a TYPE=test COVERAGE=1 build after running the tests
coverage:
	@mkdir -p $(COVDIR)
	gcov -o $(BUILDDIR)/auth $(SOURCES) > /dev/null
	@mv *.$(COVEXT) $(COVDIR)/ 2> /dev/null || true

clear: clean-objects clean-tests

clean: clear
	@$(RM) -rf $(TARGETDIR)
	@$(RM) -rf $(COVDIR)

clean-objects:
	@$(RM) -rf $(BUILDDIR)

clean-tests:
	@$(RM) -rf $(TESTBUILD)
	@$(RM) -rf $(TESTTARGET)

.PHONY: all clean clear test units integration fuzz coverage
