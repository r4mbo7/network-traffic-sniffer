TARGET   = analyseur

CC       = gcc
CFLAGS   = -Wall -g
LINKER   = gcc -o
LFLAGS	 = -lpcap
SRCDIR   = src
OBJDIR   = build
BINDIR   = bin

SOURCES  := $(wildcard $(SRCDIR)/*.c)
INCLUDES := $(wildcard $(SRCDIR)/*.h)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
rm       = rm -f
mkdir	 = mkdir

all: dir $(BINDIR)/$(TARGET)

dir: $(BINDIR) $(SRCDIR) $(OBJDIR)

$(BINDIR):
	@$(mkdir) $(BINDIR)

$(SRCDIR):
	@$(mkdir) $(SRCDIR)

$(OBJDIR):
	@$(mkdir) $(OBJDIR)

$(BINDIR)/$(TARGET): $(OBJECTS)
	@$(LINKER) $@ $(OBJECTS) $(LFLAGS)
	@echo "Linking complete!"

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully!"

.PHONEY: clean
clean:
	@$(rm) $(OBJECTS)
	@echo "Cleanup complete!"

.PHONEY: remove
remove: clean
	@$(rm) $(BINDIR)/$(TARGET)
	@echo "Executable removed!"