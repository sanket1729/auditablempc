FROM ubuntu:18.04
RUN apt update
SHELL ["/bin/bash", "-c"] 
ARG user
ARG pwd

RUN apt install -y curl gcc git

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > setup.sh
RUN sh setup.sh -y
RUN ~/.cargo/bin/rustup default stable
ARG CACHE=1
RUN git clone https://github.com/randomcyrptobuddy/auditablempc
WORKDIR auditablempc
RUN ~/.cargo/bin/cargo test -- --nocapture
CMD tail -f /dev/null
