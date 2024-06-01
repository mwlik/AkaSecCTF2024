FROM rust:latest

ENV ROCKET_ADDRESS=0.0.0.0
ENV ROCKET_PORT=1337

WORKDIR /src
COPY . .

EXPOSE 1337

RUN rustup default nightly
RUN cargo build

CMD ["cargo", "run"]
