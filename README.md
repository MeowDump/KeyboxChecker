> [!Termux Installation Guide]
> Copy-Paste the following commands in termux, if it asks for confirmation, type `y` and hit `ENTER` button in your keyboard
```bash
termux-setup-storage
pkg update && pkg upgrade -y
pkg install git python python-pip rust openssl -y
pip install --upgrade pip setuptools
git clone https://github.com/MeowDump/KeyboxChecker
export RUSTFLAGS=" -C lto=no" && export CARGO_BUILD_TARGET="$(rustc -vV | sed -n 's|host: ||p')" && pip install cryptography aiohttp colorama

```

# Usage
```bash
python main.py path/to/keybox.xml
```
