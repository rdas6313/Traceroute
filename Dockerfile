FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install required packages for building and adding repos
RUN apt-get update && apt-get install -y wget gnupg2 software-properties-common ca-certificates make iputils-ping

# Add Ubuntu Toolchain PPA manually
RUN echo "deb http://ppa.launchpad.net/ubuntu-toolchain-r/test/ubuntu focal main" > /etc/apt/sources.list.d/ubuntu-toolchain-r-ubuntu-test-focal.list && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 1E9377A2BA9EF27F

# Update and install GCC 11
RUN apt-get update && apt-get install -y gcc-11 g++-11 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 100 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 100

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app

# Build your traceroute tool
RUN make CC=gcc

ENTRYPOINT ["./Traceroute"]


