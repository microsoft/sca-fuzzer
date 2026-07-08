mkfile_path = $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir = $(dir $(mkfile_path))

dr_path := $(HOME)/.local/dynamorio/
model_path := $(HOME)/.local/dynamorio/model/

release := 11.3.0-1
dr_url := https://github.com/DynamoRIO/dynamorio/releases/download/release_11.3.0-1/DynamoRIO-Linux-11.3.0.tar.gz

CMAKE_FLAGS := -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

leak_detector_dir := $(current_dir)/leak_detector

.PHONY: all download_dr backend adapter leak-detector \
	clean-backend clean-adapter clean-leak-detector clean

all: download_dr backend adapter leak-detector
download_dr: $(dr_path)/drrun
	@echo "DynamoRIO is downloaded and ready to use."

$(dr_path)/drrun:
	mkdir -p $(dr_path)
	wget $(dr_url) -O $(dr_path)/DynamoRIO-Linux-$(release).tar.gz
	tar xf $(dr_path)/DynamoRIO-Linux-$(release).tar.gz -C $(dr_path)
	rm $(dr_path)/DynamoRIO-Linux-$(release).tar.gz
	echo "#!/usr/bin/env bash" > $(dr_path)/drrun
	echo '$(dr_path)/DynamoRIO-Linux-$(release)/bin64/drrun -disable_traces	$$@' >> $(dr_path)/drrun
	chmod +x $(dr_path)/drrun

backend:
	mkdir -p $(current_dir)/backend/build
	cd $(current_dir)/backend/build && cmake $(CMAKE_FLAGS) -DDynamoRIO_DIR=$(dr_path)/DynamoRIO-Linux-$(release)/cmake -D CMAKE_BUILD_TYPE=RelWithDebInfo $(current_dir)/backend
	make -C $(current_dir)/backend/build
	cp $(current_dir)/backend/build/libdr_model.so $(dr_path)

adapter:
	mkdir -p $(current_dir)/adapter/build
	cd $(current_dir)/adapter/build && cmake $(CMAKE_FLAGS) $(current_dir)/adapter
	make -C $(current_dir)/adapter/build
	make -C $(current_dir)/adapter/build install

leak-detector:
	mkdir -p $(leak_detector_dir)/build
	cd $(leak_detector_dir)/build && cmake $(CMAKE_FLAGS) $(leak_detector_dir)
	make -C $(leak_detector_dir)/build
	make -C $(leak_detector_dir)/build install

clean-backend:
	rm -rf $(current_dir)/backend/build

clean-adapter:
	rm -rf $(current_dir)/adapter/build

clean-leak-detector:
	rm -rf $(leak_detector_dir)/build

clean:  clean-backend clean-adapter clean-leak-detector

uninstall-dr:
	rm -rf $(dr_path)/DynamoRIO-Linux-*.tar.gz $(dr_path)/drrun

# * build dr_model

# ```
# cd adapters
# make example
# drrun -c ~/.local/dr_model/libdr_model.so --tracer ct --disable-normalization -- ./example 2
# ```
