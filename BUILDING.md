# Building

## Binary build
Builds ends up in: target/release/
Only the binares seems needed to run?


### Use develop branch
    git checkout develop
    git pull

### install rust 
    curl https://sh.rustup.rs -sSf | sh
    source $HOME/.cargo/env

### run the build setup from kilt sources
   ./scripts/init.sh 

You might need to add 'nightly-' to the file 

### Install build deps

    sudo apt-get install libclang-dev build-essential

### Build mashnet-node
    cargo build --release -p mashnet-node

### Build collator node (kilt-parachain)
   cargo build --release -p kilt-parachain

## Build snap
You might consider building in a lxc container.
    lxc launch ubuntu:20.04 kiltsnapbuild
    lxc shell kiltsnapbuild
      sudo snap install snapcraft
      git clone https://github.com/erik78se/mashnet-node
      snapcraft --destructive-mode

      
