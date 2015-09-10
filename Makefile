VERSION=0.0.1

help:
	@echo "help"
	@echo "-------------------------------------------------------"
	@echo "make help     this help"
	@echo "make clean    remove temporary files"
	@echo "make install  install this package locally"

clean:
	find . -name "*.pyc" -delete
	find . -name ".DS_Store" -delete
	rm -rf *.egg
	rm -rf *.egg-info
	rm -rf __pycache__
	rm -rf build
	rm -rf dist

version:
	@sed -i -orig /version/s/[0-9.]+/$(VERSION)/ setup.py

install:
	-pip uninstall cloudflare2loggly --yes
	pip install -e .
