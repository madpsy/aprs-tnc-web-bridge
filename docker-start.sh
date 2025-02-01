#!/bin/bash
docker run -d \
	--name tnc \
        --restart unless-stopped \
	--privileged \
	--network=host \
	-v /dev:/dev \
       	-v $(pwd)/config:/app/config \
	-v $(pwd)/logs:/app/logs \
	tnc
