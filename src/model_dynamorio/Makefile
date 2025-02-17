mkfile_path = $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir = $(dir $(mkfile_path))

dr_path := $(HOME)/.local/dynamorio/
model_path := $(HOME)/.local/dynamorio/model/

release := 11.2.0

.PHONY: all download_dr backend adapter

all: download_dr backend adapter

download_dr:
	mkdir -p $(dr_path)
	wget https://github.com/DynamoRIO/dynamorio/releases/download/release_$(release)/DynamoRIO-Linux-$(release).tar.gz -O $(dr_path)/DynamoRIO-Linux-$(release).tar.gz
	tar xf $(dr_path)/DynamoRIO-Linux-$(release).tar.gz -C $(dr_path)
	rm $(dr_path)/DynamoRIO-Linux-$(release).tar.gz
	echo "#!/usr/bin/env bash" > $(dr_path)/drrun
	echo '$(dr_path)/DynamoRIO-Linux-$(release)/bin64/drrun $$@' >> $(dr_path)/drrun
	chmod +x $(dr_path)/drrun

backend:
	mkdir -p $(model_path)/build
	cd $(model_path)/build && cmake -DDynamoRIO_DIR=$(dr_path)/DynamoRIO-Linux-$(release)/cmake --config Debug $(current_dir)/backend
	make -C $(model_path)/build
	cp $(model_path)/build/libdr_model.so $(dr_path)

adapter:
	make -C $(current_dir)/adapter




# * build dr_model

# ```
# cd adapters
# make example
# drrun -c ~/.local/dr_model/libdr_model.so --tracer ct --disable-normalization -- ./example 2
# ```
