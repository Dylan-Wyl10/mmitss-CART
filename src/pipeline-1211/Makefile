# Makefile (located in src/pipeline-1211)

.PHONY: clean build run

clean:
	rm -rf build dist *.spec __pycache__ bin/M_Solver1211

build:
	pyinstaller --clean --noconfirm --onefile new_solver.py \
		--name M_Solver1211 \
		--distpath bin

run: 
	./bin/M_Solver1211
