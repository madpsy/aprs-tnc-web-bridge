#!/bin/bash
docker run -d \
	--name tnc \
        --restart unless-stopped \
	--privileged \
	-v /dev:/dev \
       	-v $(pwd)/config:/app/config \
	-v $(pwd)/logs:/app/logs \
	-p 5001:5001 \
	-p 5002:5002 \
	tnc
